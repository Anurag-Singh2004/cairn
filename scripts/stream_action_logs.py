#!/usr/bin/env python3
"""CAIRN GitHub Actions live log streaming helper.

Executes a command as a child process, captures its stdout and stderr,
prints it immediately to the local console, and forwards batches of lines
to the CAIRN web application for real-time live terminal viewing.

Designed to be resilient: network or backend failures never fail an otherwise
successful workflow command.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

# Patterns to redact before streaming
SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{16,}", re.IGNORECASE),
]


def redact_line(line: str, known_secrets: list[str]) -> str:
    """Redact known secrets and recognizable credential patterns from a log line."""
    cleaned = line
    for sec in known_secrets:
        if sec and len(sec) >= 6 and sec in cleaned:
            cleaned = cleaned.replace(sec, "[REDACTED]")
    for pat in SECRET_PATTERNS:
        cleaned = pat.sub("[REDACTED]", cleaned)
    return cleaned


class LogForwarder:
    """Background worker that flushes batches of log lines to CAIRN ingestion API."""

    def __init__(
        self,
        url: str,
        token: str,
        stream_id: str,
        run_id: str,
        attempt: str,
        workflow: str,
        job: str,
        step: str,
        request_id: str | None,
        batch_interval: float = 0.5,
        max_batch_size: int = 50,
        known_secrets: list[str] | None = None,
    ) -> None:
        self.url = url.strip()
        self.token = token.strip()
        self.stream_id = stream_id
        self.run_id = run_id
        self.attempt = attempt
        self.workflow = workflow
        self.job = job
        self.step = step
        self.request_id = request_id
        self.batch_interval = batch_interval
        self.max_batch_size = max_batch_size
        self.known_secrets = known_secrets or []

        self.queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.enabled = bool(self.url and self.token)
        self._consecutive_failures = 0

    def start(self) -> None:
        if self.enabled:
            self.worker_thread.start()

    def enqueue_line(self, text: str) -> None:
        if not self.enabled:
            return
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        sanitized = redact_line(text, self.known_secrets)
        item = {
            "timestamp": now_iso,
            "step": self.step,
            "text": sanitized.rstrip("\r\n"),
        }
        with contextlib.suppress(queue.Full):
            self.queue.put_nowait(item)

    def stop_and_flush(self, timeout: float = 5.0) -> None:
        if not self.enabled:
            return
        self.queue.put(None)  # Sentinel to terminate
        self.stop_event.set()
        self.worker_thread.join(timeout=timeout)

    def _send_batch(self, items: list[dict[str, Any]]) -> bool:
        if not items:
            return True

        payload = {
            "stream_id": self.stream_id,
            "run_id": self.run_id,
            "attempt": self.attempt,
            "workflow": self.workflow,
            "job": self.job,
            "step": self.step,
            "request_id": self.request_id,
            "lines": items,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "cairn-log-forwarder/0.1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if 200 <= resp.status < 300:
                    self._consecutive_failures = 0
                    return True
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures <= 2:
                sys.stderr.write(
                    f"\n[stream_action_logs] Notice: log delivery to {self.url} failed: {exc}\n"
                )
        return False

    def _run_loop(self) -> None:
        pending: list[dict[str, Any]] = []
        last_flush = time.time()

        while True:
            try:
                # Calculate time to next flush interval
                elapsed = time.time() - last_flush
                wait_time = max(0.05, self.batch_interval - elapsed)
                item = self.queue.get(timeout=wait_time)
                if item is None:
                    # Sentinel reached: flush remaining and exit
                    if pending:
                        self._send_batch(pending)
                    break
                pending.append(item)
            except queue.Empty:
                pass

            now = time.time()
            if pending and (
                len(pending) >= self.max_batch_size or now - last_flush >= self.batch_interval
            ):
                self._send_batch(pending)
                pending = []
                last_flush = now


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Stream GitHub Actions command stdout/stderr to CAIRN live terminal."
    )
    parser.add_argument(
        "--step", default="Workflow Step", help="Label for current step (default: 'Workflow Step')"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("CAIRN_LOG_INGEST_URL", ""),
        help="Backend log ingestion endpoint",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("CAIRN_LOG_INGEST_TOKEN", ""),
        help="Shared ingest secret token",
    )
    parser.add_argument(
        "--run-id",
        default=os.environ.get("GITHUB_RUN_ID", "local"),
        help="GitHub run ID",
    )
    parser.add_argument(
        "--attempt",
        default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        help="GitHub run attempt",
    )
    parser.add_argument(
        "--workflow",
        default=os.environ.get("GITHUB_WORKFLOW", "local-workflow"),
        help="Workflow name",
    )
    parser.add_argument(
        "--job",
        default=os.environ.get("GITHUB_JOB", "local-job"),
        help="Job name",
    )
    parser.add_argument(
        "--request-id",
        default=os.environ.get("REQUEST_ID", ""),
        help="CAIRN correlation request ID if available",
    )
    parser.add_argument(
        "--batch-interval",
        type=float,
        default=0.5,
        help="Streaming batch interval in seconds",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Max lines per batch",
    )

    # Everything after -- is the command to run
    if "--" in sys.argv:
        split_idx = sys.argv.index("--")
        cli_args = sys.argv[1:split_idx]
        cmd_args = sys.argv[split_idx + 1 :]
    else:
        cli_args = sys.argv[1:]
        cmd_args = []

    parsed = parser.parse_args(cli_args)
    if not cmd_args:
        sys.stderr.write("Error: No command specified to execute. Use '-- <command> [args...]'\n")
        sys.exit(2)

    return parsed, cmd_args


def main() -> None:
    args, cmd = parse_args()

    # Determine stable stream ID: <run_id>-attempt-<attempt>
    stream_id = f"{args.run_id}-attempt-{args.attempt}"

    known_secrets = [
        args.token,
        os.environ.get("GITHUB_TOKEN", ""),
        os.environ.get("CAIRN_LOG_INGEST_TOKEN", ""),
    ]

    forwarder = LogForwarder(
        url=args.url,
        token=args.token,
        stream_id=stream_id,
        run_id=str(args.run_id),
        attempt=str(args.attempt),
        workflow=args.workflow,
        job=args.job,
        step=args.step,
        request_id=args.request_id or None,
        batch_interval=args.batch_interval,
        max_batch_size=args.batch_size,
        known_secrets=[s for s in known_secrets if s],
    )

    if not forwarder.enabled:
        sys.stderr.write(
            "[stream_action_logs] Remote streaming not configured "
            "(CAIRN_LOG_INGEST_URL or CAIRN_LOG_INGEST_TOKEN absent). "
            "Command running locally.\n"
        )
    else:
        forwarder.start()

    # Execute subprocess
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            errors="replace",
        )
    except Exception as exc:
        sys.stderr.write(f"[stream_action_logs] Failed to execute {cmd}: {exc}\n")
        forwarder.stop_and_flush()
        sys.exit(127)

    try:
        # Read lines as they are produced in real-time
        if proc.stdout:
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                forwarder.enqueue_line(line)
    except KeyboardInterrupt:
        proc.terminate()
        sys.exit(130)
    finally:
        proc.wait()
        forwarder.stop_and_flush(timeout=4.0)

    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
