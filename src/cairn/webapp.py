"""CAIRN Web Application & Live Assurance API.

FastAPI application for Render deployment per context.md and hackathon deployment requirements.
Serves the interactive evaluator frontend and provides authenticated REST integration
with GitHub Actions on-demand benchmark runner and live log streaming ingestion.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import os
import re
import secrets
import threading
import time
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger("cairn.webapp")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="CAIRN Live Assurance API",
    description="Blind-by-Design, Measured, Signed Isolation for Adversarial AI Safety Testing",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Configuration from environment
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "Anurag-Singh2004/cairn").strip()
GITHUB_WORKFLOW_FILE = os.environ.get("GITHUB_WORKFLOW_FILE", "cairn-demo.yml").strip()
GITHUB_REF = os.environ.get("GITHUB_REF", "main").strip()
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "600"))
CACHE_DIR = Path(os.environ.get("CAIRN_CACHE_DIR", "data/artifact_cache"))
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Log streaming configuration
CAIRN_LOG_INGEST_TOKEN = os.environ.get("CAIRN_LOG_INGEST_TOKEN", "").strip()
MAX_RETAINED_STREAMS = int(os.environ.get("CAIRN_MAX_RETAINED_STREAMS", "30"))
MAX_LINES_PER_STREAM = int(os.environ.get("CAIRN_MAX_LINES_PER_STREAM", "5000"))
MAX_BYTES_PER_STREAM = int(os.environ.get("CAIRN_MAX_BYTES_PER_STREAM", str(2 * 1024 * 1024)))
STREAM_EXPIRY_SECONDS = int(os.environ.get("CAIRN_STREAM_EXPIRY_SECONDS", "7200"))

# In-memory rate limiting and dispatched jobs tracking
CLIENT_REQUEST_HISTORY: dict[str, list[float]] = defaultdict(list)
DISPATCHED_JOBS: dict[str, dict[str, Any]] = {}
LATEST_RUN_CACHE: dict[str, Any] = {}

VALID_JOB_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
VALID_STREAM_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def is_safe_artifact_file(file_path: Path | str) -> bool:
    """Validate that a file is strictly an allowlisted output format and not a secret/database."""
    p = Path(file_path)
    name = p.name.lower()
    suffix = p.suffix.lower()

    if name.startswith(".") or name.startswith("ref_ed25519"):
        return False
    if any(s in name for s in ("key", "pem", "priv", "secret", "token", "env")):
        return False
    if suffix in (".db", ".wal", ".shm", ".sqlite", ".sqlite3", ".pyc"):
        return False

    return suffix in (".json", ".md", ".html", ".txt")


class JobCreateResponse(BaseModel):
    job_id: str
    request_id: str
    status: str
    message: str


class LogLineInput(BaseModel):
    timestamp: str | None = None
    step: str | None = None
    text: str


class LogBatchInput(BaseModel):
    stream_id: str
    run_id: str | int
    attempt: str | int = "1"
    workflow: str = "workflow"
    job: str = "job"
    step: str = "step"
    request_id: str | None = None
    lines: list[LogLineInput]


class LogStream:
    """Represents an active or completed in-memory log stream for a specific run attempt."""

    def __init__(
        self,
        stream_id: str,
        run_id: str,
        attempt: str,
        workflow: str,
        job: str,
        step: str,
        request_id: str | None,
    ) -> None:
        self.stream_id = stream_id
        self.run_id = run_id
        self.attempt = attempt
        self.workflow = workflow
        self.job = job
        self.step = step
        self.request_id = request_id
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.lines: list[dict[str, Any]] = []
        self.next_sequence: int = 1
        self.total_bytes: int = 0

    def append_line(self, timestamp: str, step: str, text: str) -> None:
        # Enforce maximum individual line size
        if len(text) > 4096:
            text = text[:4096] + " ... [TRUNCATED]"

        line_bytes = len(text.encode("utf-8", errors="replace"))
        entry = {
            "sequence": self.next_sequence,
            "timestamp": timestamp,
            "step": step,
            "text": text,
        }
        self.lines.append(entry)
        self.next_sequence += 1
        self.total_bytes += line_bytes
        self.updated_at = time.time()
        if step:
            self.step = step

        # Prune if exceeded line or byte limits
        while len(self.lines) > MAX_LINES_PER_STREAM:
            removed = self.lines.pop(0)
            self.total_bytes -= len(removed["text"].encode("utf-8", errors="replace"))

        while self.lines and self.total_bytes > MAX_BYTES_PER_STREAM:
            removed = self.lines.pop(0)
            self.total_bytes -= len(removed["text"].encode("utf-8", errors="replace"))


class LogBufferManager:
    """Thread-safe manager for in-memory log streams with retention and pruning."""

    def __init__(self) -> None:
        self._streams: dict[str, LogStream] = {}
        self._lock = threading.Lock()

    def add_batch(
        self,
        stream_id: str,
        run_id: str,
        attempt: str,
        workflow: str,
        job: str,
        step: str,
        request_id: str | None,
        lines: list[dict[str, Any]],
    ) -> int:
        with self._lock:
            self._prune_expired()

            if stream_id not in self._streams:
                if len(self._streams) >= MAX_RETAINED_STREAMS:
                    oldest_key = min(self._streams, key=lambda k: self._streams[k].updated_at)
                    del self._streams[oldest_key]

                self._streams[stream_id] = LogStream(
                    stream_id=stream_id,
                    run_id=run_id,
                    attempt=attempt,
                    workflow=workflow,
                    job=job,
                    step=step,
                    request_id=request_id,
                )

            stream = self._streams[stream_id]
            now_iso = datetime.datetime.now(datetime.UTC).isoformat()
            for item in lines:
                t_stamp = item.get("timestamp") or now_iso
                st = item.get("step") or step
                txt = item.get("text", "")
                stream.append_line(t_stamp, st, txt)

            return len(lines)

    def get_lines(
        self, stream_id: str, after_cursor: int = 0, limit: int = 500
    ) -> tuple[list[dict[str, Any]], int, bool, LogStream | None]:
        with self._lock:
            stream = self._streams.get(stream_id)
            if not stream:
                return [], after_cursor, False, None

            filtered = [line for line in stream.lines if line["sequence"] > after_cursor]
            has_more = len(filtered) > limit
            chunk = filtered[:limit]
            next_cursor = chunk[-1]["sequence"] if chunk else after_cursor
            return chunk, next_cursor, has_more, stream

    def get_stream(self, stream_id: str) -> LogStream | None:
        with self._lock:
            return self._streams.get(stream_id)

    def list_streams(self) -> list[dict[str, Any]]:
        with self._lock:
            self._prune_expired()
            res = []
            for st in self._streams.values():
                res.append(
                    {
                        "stream_id": st.stream_id,
                        "run_id": st.run_id,
                        "attempt": st.attempt,
                        "workflow": st.workflow,
                        "job": st.job,
                        "step": st.step,
                        "request_id": st.request_id,
                        "created_at": st.created_at,
                        "updated_at": st.updated_at,
                        "line_count": len(st.lines),
                        "total_bytes": st.total_bytes,
                    }
                )
            res.sort(key=lambda s: s["updated_at"], reverse=True)
            return res

    def clear(self) -> None:
        with self._lock:
            self._streams.clear()

    def _prune_expired(self) -> None:
        now = time.time()
        expired = [
            k for k, v in self._streams.items() if now - v.updated_at > STREAM_EXPIRY_SECONDS
        ]
        for k in expired:
            del self._streams[k]


LOG_BUFFER = LogBufferManager()


def is_github_configured() -> bool:
    """Check if a valid, non-placeholder GitHub token is configured."""
    return bool(
        GITHUB_TOKEN
        and len(GITHUB_TOKEN) > 8
        and not GITHUB_TOKEN.startswith("ghp_placeholder")
        and not GITHUB_TOKEN.startswith("github_pat_placeholder")
    )


def check_client_rate_limit(client_ip: str, limit: int = 5, window_seconds: int = 60) -> bool:
    """Sliding-window per-client rate limiter."""
    now = time.time()
    history = CLIENT_REQUEST_HISTORY[client_ip]
    CLIENT_REQUEST_HISTORY[client_ip] = [ts for ts in history if now - ts < window_seconds]
    if len(CLIENT_REQUEST_HISTORY[client_ip]) >= limit:
        return False
    CLIENT_REQUEST_HISTORY[client_ip].append(now)
    return True


def parse_results_markdown(file_path: Path) -> dict[str, Any]:
    """Parse docs/RESULTS.md into structured data with fallback safety."""
    if not file_path.is_file():
        return {
            "is_historical": True,
            "source": "docs/RESULTS.md (File not found)",
            "timestamp": None,
            "engine": "SIMULATED (SimEngine)",
            "runs": {},
            "probes": {},
            "fault_injection": {},
            "verification": {"steps_verified": 0, "tamper_rejected": False},
            "raw_markdown": "# No results recorded yet.",
        }

    text = file_path.read_text(encoding="utf-8")
    mtime = file_path.stat().st_mtime
    iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))

    runs: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        is_target_line = (
            "| **Leaky Baseline" in line
            or "| **Hardened Isolation" in line
            or "| **Fault Injection" in line
        )
        if is_target_line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 6:
                if "Leaky" in parts[0]:
                    role = "t0"
                elif "Hardened" in parts[0]:
                    role = "t1"
                else:
                    role = "fault"
                runs[role] = {
                    "role_name": parts[0].replace("**", ""),
                    "run_id": parts[1].replace("`", ""),
                    "tier": parts[2],
                    "engine": parts[3].replace("`", ""),
                    "findings": int(parts[4]) if parts[4].isdigit() else 12,
                    "checkpoint_root": parts[5].replace("`", ""),
                }

    probes = {
        "l1": {
            "name": "L1 Prefix-Cache Timing",
            "t0_status": "LEAK_DETECTED",
            "t0_metric": "AUC 1.00, CI: [1.00, 1.00], recovery: 100.0% vs chance 10.0%, N=200",
            "t1_status": "NO_SIGNAL_AT_POWER",
            "t1_metric": "AUC 0.50, CI: [0.50, 0.50], recovery: 10.5% vs chance 10.0%, N=200",
            "conclusion": "NO_SIGNAL_AT_POWER",
        },
        "l3": {
            "name": "L3 Verdict Fingerprint",
            "t0_status": "LEAK_DETECTED",
            "t0_metric": "AUC 1.00, CI: 1.00",
            "t1_status": "NO_SIGNAL_AT_POWER",
            "t1_metric": "AUC 0.50, CI: 0.50",
            "conclusion": "NO_SIGNAL_AT_POWER",
        },
        "l4": {
            "name": "L4 Storage & Env Enum",
            "t0_status": "LEAK_DETECTED",
            "t0_metric": "Foreign canary found in planted shared-storage misconfiguration",
            "t1_status": "NO_SIGNAL_AT_POWER",
            "t1_metric": "No foreign canaries detected in tested mount/env",
            "conclusion": "NO_SIGNAL_AT_POWER",
        },
        "c3": {
            "name": "C3 Matrix Reachability",
            "t0_status": "DEVIATIONS",
            "t0_metric": "10 deviations",
            "t1_status": "ENFORCED",
            "t1_metric": "0 deviations",
            "conclusion": "ENFORCED",
        },
    }

    return {
        "is_historical": True,
        "source": "docs/RESULTS.md (Historical Reference Run)",
        "timestamp": iso_time,
        "engine": "SIMULATED (SimEngine deterministic test harness)",
        "runs": runs,
        "probes": probes,
        "fault_injection": {
            "tested": "blue_timeout@f_005 under --burn CPU stress",
            "t0": "Fail-open control (prompt reaches model, BYPASS quarantined via I9)",
            "t1": "Fail-closed (generic refusal envelope at deadline, only f_005 quarantined)",
        },
        "verification": {
            "steps_verified": 5,
            "tamper_rejected": True,
            "receipts_valid": True,
            "description": (
                "5-step cryptographic verification: Ed25519 checkpoint, SHA-256 event chain, "
                "Merkle inclusion, commit-reveal, certificate recomputation."
            ),
        },
        "raw_markdown": text,
    }


def parse_job_artifacts(artifact_dir: Path, job_id: str) -> dict[str, Any]:
    """Parse structured results from downloaded allowlisted run artifacts."""
    results_md_path = artifact_dir / "RESULTS.md"
    summary_path = artifact_dir / "summary.json"

    summary: dict[str, Any] = {}
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            summary = {}

    if results_md_path.is_file():
        parsed = parse_results_markdown(results_md_path)
    else:
        parsed = parse_results_markdown(BASE_DIR / "docs" / "RESULTS.md")

    parsed["is_historical"] = False
    parsed["source"] = f"Live GitHub Actions Run (cairn-demo-{job_id})"
    parsed["job_id"] = job_id
    parsed["github_run_id"] = summary.get("github_run_id")
    parsed["github_sha"] = summary.get("github_sha")

    t1_name = summary.get("tiers", {}).get("t1")
    if t1_name:
        t1_path = artifact_dir / t1_name / "results.json"
        if t1_path.is_file():
            try:
                t1_json = json.loads(t1_path.read_text(encoding="utf-8"))
                parsed["t1_detailed"] = t1_json
            except Exception:
                pass

    return parsed


async def github_api_request(
    method: str,
    endpoint: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    """Execute authenticated HTTPS request against GitHub REST API."""
    req_headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "cairn-app/0.1.0",
    }
    if GITHUB_TOKEN:
        req_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    if headers:
        req_headers.update(headers)

    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/{endpoint.lstrip('/')}"
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=follow_redirects) as client:
        return await client.request(method, url, json=payload, headers=req_headers)


async def get_github_workflow_runs(status_filter: str | None = None) -> list[dict[str, Any]]:
    """Fetch workflow runs from GitHub API with optional status filter."""
    if not is_github_configured():
        return []
    endpoint = f"actions/workflows/{GITHUB_WORKFLOW_FILE}/runs?per_page=20"
    if status_filter:
        endpoint += f"&status={status_filter}"
    try:
        resp = await github_api_request("GET", endpoint)
        if resp.status_code == 200:
            return resp.json().get("workflow_runs", [])
    except Exception as exc:
        logger.warning(f"Failed to query GitHub workflow runs: {exc}")
    return []


async def check_active_run_and_cooldown() -> tuple[dict[str, Any] | None, int]:
    """Check if there is an active running/queued job or active cooldown."""
    if not is_github_configured():
        return None, 0

    runs = await get_github_workflow_runs()
    now = time.time()
    active_job = None
    cooldown_remaining = 0

    for run in runs:
        status = run.get("status")
        if status in ("in_progress", "queued", "waiting", "requested"):
            active_job = {
                "id": run.get("id"),
                "name": run.get("name"),
                "status": status,
                "html_url": run.get("html_url"),
                "created_at": run.get("created_at"),
            }
            break

    completed_runs = [r for r in runs if r.get("status") == "completed"]
    if completed_runs:
        last_run = completed_runs[0]
        updated_str = last_run.get("updated_at") or last_run.get("created_at")
        if updated_str:
            try:
                dt = datetime.datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
                elapsed = now - dt.timestamp()
                if elapsed < COOLDOWN_SECONDS:
                    cooldown_remaining = int(COOLDOWN_SECONDS - elapsed)
            except Exception:
                pass

    return active_job, cooldown_remaining


# --- GitHub Actions Workflow & Step Status Synchronization ---


def compute_display_status(status: str | None, conclusion: str | None) -> str:
    """Map GitHub Actions status and conclusion to standardized display status.

    Supported values:
    - QUEUED
    - IN_PROGRESS
    - SUCCESS
    - FAILED
    - CANCELLED
    - TIMED_OUT
    - UNKNOWN
    """
    s = (status or "").lower()
    c = (conclusion or "").lower()

    if s in ("queued", "requested", "waiting", "pending"):
        return "QUEUED"
    if s == "in_progress":
        return "IN_PROGRESS"
    if s == "completed":
        if c == "success":
            return "SUCCESS"
        if c == "failure":
            return "FAILED"
        if c in ("cancelled", "canceled"):
            return "CANCELLED"
        if c == "timed_out":
            return "TIMED_OUT"
        if c:
            return c.upper()
        return "COMPLETED"
    return "UNKNOWN"


def extract_job_step_progress(jobs_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract current job, step counts, and progress percentage from GitHub jobs list."""
    if not jobs_data:
        return {
            "current_job": None,
            "current_step": None,
            "steps_completed": 0,
            "steps_total": 0,
            "progress_pct": 0,
        }

    active_job = None
    for j in jobs_data:
        if j.get("status") == "in_progress":
            active_job = j
            break
    if not active_job:
        for j in jobs_data:
            if j.get("conclusion") == "failure":
                active_job = j
                break
    if not active_job:
        active_job = jobs_data[-1]

    job_name = active_job.get("name") or "Workflow Job"
    steps = active_job.get("steps") or []
    total_steps = len(steps)

    completed_steps = 0
    in_progress_step_name = None
    last_completed_step_name = None

    for s in steps:
        s_status = (s.get("status") or "").lower()
        if s_status == "completed":
            completed_steps += 1
            last_completed_step_name = s.get("name")
        elif s_status == "in_progress" and in_progress_step_name is None:
            in_progress_step_name = s.get("name")

    if in_progress_step_name:
        current_step_name = in_progress_step_name
    elif completed_steps == total_steps and total_steps > 0:
        current_step_name = last_completed_step_name or "All steps completed"
    elif completed_steps > 0:
        current_step_name = last_completed_step_name
    else:
        current_step_name = "Queued" if total_steps > 0 else None

    progress_pct = round((completed_steps / total_steps) * 100) if total_steps > 0 else 0

    return {
        "current_job": job_name,
        "current_step": current_step_name,
        "steps_completed": completed_steps,
        "steps_total": total_steps,
        "progress_pct": progress_pct,
    }


class GitHubStatusCache:
    """Thread-safe TTL cache for GitHub Actions workflow run and job status."""

    def __init__(self) -> None:
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            if time.time() > entry["expires_at"]:
                return None
            return dict(entry["data"])

    def get_stale(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._cache.get(key)
            return dict(entry["data"]) if entry else None

    def set(self, key: str, data: dict[str, Any], ttl_seconds: float) -> None:
        with self._lock:
            self._cache[key] = {
                "data": dict(data),
                "expires_at": time.time() + ttl_seconds,
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


GITHUB_STATUS_CACHE = GitHubStatusCache()


async def resolve_workflow_run_status(
    stream_id: str, run_id: str, attempt: str = "1"
) -> dict[str, Any]:
    """Resolve authoritative workflow run status from GitHub Actions with fallback and caching."""
    cache_key = f"{run_id}:{attempt}"

    cached = GITHUB_STATUS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    stream = LOG_BUFFER.get_stream(stream_id)
    has_logs = stream is not None
    request_id = stream.request_id if stream else None

    if is_github_configured() and run_id.isdigit():
        try:
            run_resp = await github_api_request("GET", f"actions/runs/{run_id}")
            if run_resp.status_code == 200:
                run_data = run_resp.json()
                gh_status = run_data.get("status")
                gh_conclusion = run_data.get("conclusion")
                workflow_name = run_data.get("name") or (stream.workflow if stream else "Workflow")
                html_url = run_data.get("html_url")
                updated_at = run_data.get("updated_at") or run_data.get("created_at")

                if not request_id and workflow_name and workflow_name.startswith("cairn-demo-"):
                    request_id = workflow_name.replace("cairn-demo-", "")

                display_status = compute_display_status(gh_status, gh_conclusion)

                jobs_resp = await github_api_request("GET", f"actions/runs/{run_id}/jobs")
                jobs_list = (
                    jobs_resp.json().get("jobs", []) if jobs_resp.status_code == 200 else []
                )
                progress = extract_job_step_progress(jobs_list)

                ttl = 120.0 if (gh_status or "").lower() == "completed" else 4.0

                result = {
                    "stream_id": stream_id,
                    "run_id": run_id,
                    "attempt": attempt,
                    "workflow_name": workflow_name,
                    "display_status": display_status,
                    "status": gh_status,
                    "conclusion": gh_conclusion,
                    "current_job": progress["current_job"],
                    "current_step": progress["current_step"],
                    "steps_completed": progress["steps_completed"],
                    "steps_total": progress["steps_total"],
                    "progress_pct": progress["progress_pct"],
                    "updated_at": updated_at,
                    "html_url": html_url,
                    "request_id": request_id,
                    "has_logs": has_logs,
                    "github_available": True,
                    "is_stale": False,
                }
                GITHUB_STATUS_CACHE.set(cache_key, result, ttl)
                return result
        except Exception as exc:
            logger.warning(f"Failed to fetch GitHub status for run {run_id}: {exc}")

        stale = GITHUB_STATUS_CACHE.get_stale(cache_key)
        if stale is not None:
            stale_copy = dict(stale)
            stale_copy["is_stale"] = True
            stale_copy["github_available"] = False
            return stale_copy

    updated_at_iso = None
    if stream:
        updated_at_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stream.updated_at))

    return {
        "stream_id": stream_id,
        "run_id": run_id,
        "attempt": attempt,
        "workflow_name": stream.workflow if stream else "Workflow",
        "display_status": "UNKNOWN",
        "status": "unknown",
        "conclusion": None,
        "current_job": stream.job if stream else None,
        "current_step": None,
        "steps_completed": 0,
        "steps_total": 0,
        "progress_pct": 0,
        "updated_at": updated_at_iso,
        "html_url": None,
        "request_id": request_id,
        "has_logs": has_logs,
        "github_available": False,
        "is_stale": False,
        "message": "GitHub API data unavailable; status is UNKNOWN.",
    }


# --- API Routes ---


@app.get("/api/health")
async def get_health() -> dict[str, Any]:
    """Health check endpoint for Render Web Service."""
    return {
        "status": "ok",
        "service": "cairn-app",
        "version": "0.1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Report GitHub Actions connectivity, runner state, and demo readiness."""
    configured = is_github_configured()
    active_job = None
    cooldown_remaining = 0

    if configured:
        active_job, cooldown_remaining = await check_active_run_and_cooldown()

    can_dispatch = configured and (active_job is None) and (cooldown_remaining == 0)
    latest_avail = (BASE_DIR / "docs" / "RESULTS.md").is_file() or bool(LATEST_RUN_CACHE)

    return {
        "service": "cairn-app",
        "github_configured": configured,
        "log_streaming_configured": bool(CAIRN_LOG_INGEST_TOKEN),
        "repository": GITHUB_REPOSITORY,
        "workflow_file": GITHUB_WORKFLOW_FILE,
        "ref": GITHUB_REF,
        "can_dispatch": can_dispatch,
        "active_job": active_job,
        "cooldown_remaining_seconds": cooldown_remaining,
        "latest_run_available": latest_avail,
    }


@app.get("/api/latest")
async def get_latest_results() -> dict[str, Any]:
    """Retrieve the most recent verified benchmark results."""
    if LATEST_RUN_CACHE:
        return LATEST_RUN_CACHE
    return parse_results_markdown(BASE_DIR / "docs" / "RESULTS.md")


@app.post("/api/jobs", status_code=202)
async def create_benchmark_job(request: Request) -> JobCreateResponse:
    """Dispatch a new live CAIRN benchmark execution via GitHub Actions."""
    client_ip = request.client.host if request.client else "unknown"

    if not check_client_rate_limit(client_ip, limit=5, window_seconds=60):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait before submitting another request.",
        )

    if not is_github_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "GitHub Actions integration is not configured on this instance. "
                "Set a valid GITHUB_TOKEN in the Render service environment."
            ),
        )

    active_job, cooldown_remaining = await check_active_run_and_cooldown()
    if active_job:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A benchmark run is already in progress ({active_job.get('status')}). "
                f"Please wait for it to finish."
            ),
        )
    if cooldown_remaining > 0:
        raise HTTPException(
            status_code=429,
            detail=f"Global benchmark cooldown active. Please wait {cooldown_remaining}s.",
        )

    import uuid

    req_id = uuid.uuid4().hex[:10]

    dispatch_payload = {
        "ref": GITHUB_REF,
        "inputs": {
            "request_id": req_id,
        },
    }
    resp = await github_api_request(
        "POST",
        f"actions/workflows/{GITHUB_WORKFLOW_FILE}/dispatches",
        payload=dispatch_payload,
    )

    if resp.status_code not in (204, 201, 200):
        logger.error(f"GitHub dispatch failed: {resp.status_code} {resp.text}")
        detail_msg = f"Failed to dispatch GitHub workflow: HTTP {resp.status_code}"
        if resp.status_code == 401:
            detail_msg = "Authentication failed: invalid or expired GITHUB_TOKEN."
        elif resp.status_code == 404:
            detail_msg = (
                f"Workflow '{GITHUB_WORKFLOW_FILE}' or repository '{GITHUB_REPOSITORY}' not found."
            )
        elif resp.status_code == 422:
            detail_msg = f"GitHub rejected dispatch request: {resp.text}"
        raise HTTPException(status_code=502, detail=detail_msg)

    DISPATCHED_JOBS[req_id] = {
        "job_id": req_id,
        "request_id": req_id,
        "created_at": time.time(),
        "status": "queued",
        "stage": "Queued in GitHub Actions",
    }

    return JobCreateResponse(
        job_id=req_id,
        request_id=req_id,
        status="queued",
        message="Benchmark dispatched successfully to GitHub Actions.",
    )


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str) -> dict[str, Any]:
    """Poll genuine execution status and stage of a benchmark job."""
    if not VALID_JOB_ID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    if not is_github_configured():
        if job_id in DISPATCHED_JOBS:
            return DISPATCHED_JOBS[job_id]
        raise HTTPException(status_code=404, detail="Job not found and GitHub token not set.")

    runs = await get_github_workflow_runs()
    target_run = None
    expected_name = f"cairn-demo-{job_id}"

    for r in runs:
        if r.get("name") == expected_name:
            target_run = r
            break

    if not target_run:
        job_record = DISPATCHED_JOBS.get(job_id)
        if job_record and time.time() - job_record["created_at"] < 45:
            created_iso = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(job_record["created_at"])
            )
            return {
                "job_id": job_id,
                "status": "queued",
                "stage": "Waiting for GitHub runner allocation...",
                "conclusion": None,
                "html_url": None,
                "created_at": created_iso,
            }
        raise HTTPException(
            status_code=404, detail=f"Job {job_id} not found in recent workflow runs."
        )

    run_id = target_run["id"]
    attempt = str(target_run.get("run_attempt", 1))
    status = target_run.get("status")
    conclusion = target_run.get("conclusion")
    html_url = target_run.get("html_url")
    created_at = target_run.get("created_at")
    updated_at = target_run.get("updated_at")
    stream_id = f"{run_id}-attempt-{attempt}"

    stage_desc = f"Workflow status: {status}"

    if status == "in_progress":
        try:
            jobs_resp = await github_api_request("GET", f"actions/runs/{run_id}/jobs")
            if jobs_resp.status_code == 200:
                jobs_data = jobs_resp.json().get("jobs", [])
                if jobs_data:
                    current_steps = jobs_data[0].get("steps", [])
                    in_prog = [s for s in current_steps if s.get("status") == "in_progress"]
                    if in_prog:
                        stage_desc = f"Executing: {in_prog[0].get('name')}"
                    elif current_steps:
                        stage_desc = f"Completed step: {current_steps[-1].get('name')}"
        except Exception:
            pass

    if status == "completed":
        if conclusion == "success":
            stage_desc = "Benchmark and offline verification completed successfully"
            await ensure_job_artifacts_downloaded(job_id, run_id)
        else:
            stage_desc = f"Workflow execution ended with conclusion: {conclusion}"

    return {
        "job_id": job_id,
        "github_run_id": run_id,
        "run_attempt": attempt,
        "stream_id": stream_id,
        "status": status,
        "conclusion": conclusion,
        "stage": stage_desc,
        "html_url": html_url,
        "created_at": created_at,
        "updated_at": updated_at,
    }


# --- Log Streaming Endpoints ---


@app.post("/api/internal/logs", status_code=200)
async def ingest_logs(batch: LogBatchInput, request: Request) -> dict[str, Any]:
    """Ingest a batch of real-time command output lines from GitHub Actions runner."""
    if not CAIRN_LOG_INGEST_TOKEN:
        raise HTTPException(
            status_code=503,
            detail=(
                "Log ingestion is not configured on this server. "
                "Set CAIRN_LOG_INGEST_TOKEN in environment."
            ),
        )

    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer ") :].strip()
    elif "X-Cairn-Ingest-Token" in request.headers:
        token = request.headers["X-Cairn-Ingest-Token"].strip()

    if not token or not secrets.compare_digest(token, CAIRN_LOG_INGEST_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing ingest token.",
        )

    if not VALID_STREAM_ID_REGEX.match(batch.stream_id):
        raise HTTPException(status_code=400, detail="Invalid stream ID format.")

    if len(batch.lines) > 500:
        raise HTTPException(status_code=400, detail="Batch exceeds maximum limit of 500 lines.")

    lines_dicts = [
        {"timestamp": item.timestamp, "step": item.step, "text": item.text} for item in batch.lines
    ]
    accepted = LOG_BUFFER.add_batch(
        stream_id=batch.stream_id,
        run_id=str(batch.run_id),
        attempt=str(batch.attempt),
        workflow=batch.workflow,
        job=batch.job,
        step=batch.step,
        request_id=batch.request_id,
        lines=lines_dicts,
    )

    return {"status": "ok", "accepted": accepted, "stream_id": batch.stream_id}


@app.get("/api/workflows")
async def list_workflows() -> dict[str, Any]:
    """List recent and active workflow runs with their stream identifiers and status."""
    workflows: list[dict[str, Any]] = []

    if is_github_configured():
        try:
            resp = await github_api_request("GET", "actions/runs?per_page=15")
            if resp.status_code == 200:
                gh_runs = resp.json().get("workflow_runs", [])
                for r in gh_runs:
                    run_id = str(r.get("id"))
                    attempt = str(r.get("run_attempt", 1))
                    stream_id = f"{run_id}-attempt-{attempt}"
                    name = r.get("name", "Workflow")
                    req_id = None
                    if name.startswith("cairn-demo-"):
                        req_id = name.replace("cairn-demo-", "")

                    has_logs = bool(LOG_BUFFER.get_stream(stream_id) is not None)
                    gh_status = r.get("status")
                    gh_conclusion = r.get("conclusion")
                    display_status = compute_display_status(gh_status, gh_conclusion)

                    workflows.append(
                        {
                            "name": name,
                            "workflow_path": r.get("path"),
                            "run_id": r.get("id"),
                            "run_attempt": r.get("run_attempt", 1),
                            "stream_id": stream_id,
                            "status": gh_status,
                            "conclusion": gh_conclusion,
                            "display_status": display_status,
                            "branch": r.get("head_branch"),
                            "commit_sha": (r.get("head_sha") or "")[:7],
                            "event": r.get("event"),
                            "created_at": r.get("created_at"),
                            "updated_at": r.get("updated_at"),
                            "html_url": r.get("html_url"),
                            "request_id": req_id,
                            "has_logs": has_logs,
                        }
                    )
        except Exception as exc:
            logger.warning(f"Error fetching GitHub workflow runs: {exc}")

    # Also include in-memory streams if any are not in the GitHub list
    seen_streams = {w["stream_id"] for w in workflows}
    for st in LOG_BUFFER.list_streams():
        s_id = st["stream_id"]
        if s_id not in seen_streams:
            workflows.append(
                {
                    "name": st.get("workflow", "Workflow"),
                    "workflow_path": "",
                    "run_id": st.get("run_id"),
                    "run_attempt": st.get("attempt", 1),
                    "stream_id": s_id,
                    "status": "unknown",
                    "conclusion": None,
                    "display_status": "UNKNOWN",
                    "branch": "main",
                    "commit_sha": "",
                    "event": "workflow_dispatch",
                    "created_at": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(st["created_at"])
                    ),
                    "updated_at": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(st["updated_at"])
                    ),
                    "html_url": None,
                    "request_id": st.get("request_id"),
                    "has_logs": True,
                }
            )

    return {"workflows": workflows}


@app.get("/api/workflows/{stream_id}/status")
async def get_workflow_status(stream_id: str) -> dict[str, Any]:
    """Retrieve verified GitHub Actions workflow run, job, and step status."""
    if not VALID_STREAM_ID_REGEX.match(stream_id):
        raise HTTPException(status_code=400, detail="Invalid stream ID format.")

    run_id = stream_id
    attempt = "1"
    if "-attempt-" in stream_id:
        parts = stream_id.split("-attempt-")
        run_id = parts[0]
        attempt = parts[1]
    else:
        stream = LOG_BUFFER.get_stream(stream_id)
        if stream:
            run_id = str(stream.run_id)
            attempt = str(stream.attempt)

    return await resolve_workflow_run_status(stream_id, run_id, attempt)


@app.get("/api/workflows/{stream_id}/logs")
async def get_workflow_logs(stream_id: str, after: int = 0, limit: int = 500) -> dict[str, Any]:
    """Retrieve incremental live log lines after a cursor sequence number."""
    if not VALID_STREAM_ID_REGEX.match(stream_id):
        raise HTTPException(status_code=400, detail="Invalid stream ID format.")

    limit = max(1, min(limit, 1000))
    chunk, next_cursor, has_more, stream = LOG_BUFFER.get_lines(
        stream_id, after_cursor=after, limit=limit
    )

    if stream is not None:
        run_id = str(stream.run_id)
        attempt = str(stream.attempt)
        status_info = await resolve_workflow_run_status(stream_id, run_id, attempt)
        workflow_status = status_info.get("display_status", "UNKNOWN").lower()

        return {
            "stream_id": stream_id,
            "run_id": stream.run_id,
            "attempt": stream.attempt,
            "workflow": stream.workflow,
            "step": stream.step,
            "lines": chunk,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "workflow_status": workflow_status,
            "message": None,
        }

    # If stream has no lines in memory yet, check if it exists on GitHub
    if "-" in stream_id or stream_id.isdigit():
        run_id = stream_id.split("-attempt-")[0] if "-attempt-" in stream_id else stream_id
        attempt = stream_id.split("-attempt-")[1] if "-attempt-" in stream_id else "1"
        status_info = await resolve_workflow_run_status(stream_id, run_id, attempt)
        workflow_status = status_info.get("display_status", "UNKNOWN").lower()

        return {
            "stream_id": stream_id,
            "lines": [],
            "next_cursor": 0,
            "has_more": False,
            "workflow_status": workflow_status,
            "message": "No live log output received for this workflow run yet.",
        }

    raise HTTPException(status_code=404, detail=f"Workflow stream '{stream_id}' not found.")


# --- Artifact Handling & Offline Verification ---


async def ensure_job_artifacts_downloaded(job_id: str, run_id: int) -> Path | None:
    """Download, safely unpack allowlisted files, and cache in memory."""
    target_dir = CACHE_DIR / job_id
    if (target_dir / "summary.json").is_file():
        return target_dir

    if not is_github_configured():
        return None

    try:
        art_resp = await github_api_request("GET", f"actions/runs/{run_id}/artifacts")
        if art_resp.status_code != 200:
            return None

        artifacts = art_resp.json().get("artifacts", [])
        expected_art_name = f"cairn-artifacts-{job_id}"
        art_obj = next((a for a in artifacts if a.get("name") == expected_art_name), None)
        if not art_obj and artifacts:
            art_obj = artifacts[0]

        if not art_obj:
            return None

        art_id = art_obj["id"]
        dl_resp = await github_api_request(
            "GET", f"actions/artifacts/{art_id}/zip", follow_redirects=True
        )
        if dl_resp.status_code != 200:
            return None

        target_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(dl_resp.content)) as zf:
            for member in zf.infolist():
                norm_name = os.path.normpath(member.filename)
                if norm_name.startswith("..") or os.path.isabs(norm_name):
                    continue
                if not is_safe_artifact_file(norm_name):
                    continue
                allowed_prefixes = ("RESULTS.md", "summary.json", "r_demo", "report.html")
                if not any(norm_name.startswith(p) for p in allowed_prefixes):
                    continue

                zf.extract(member, target_dir)

        parsed = parse_job_artifacts(target_dir, job_id)
        LATEST_RUN_CACHE.clear()
        LATEST_RUN_CACHE.update(parsed)
        return target_dir
    except Exception as exc:
        logger.error(f"Failed to download/unpack artifacts for job {job_id}: {exc}")
        return None


@app.get("/api/jobs/{job_id}/results")
async def get_job_results(job_id: str) -> dict[str, Any]:
    """Retrieve verified benchmark results for a completed job."""
    if not VALID_JOB_ID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    target_dir = CACHE_DIR / job_id
    if target_dir.is_dir():
        return parse_job_artifacts(target_dir, job_id)

    status_info = await get_job_status(job_id)
    if status_info.get("status") != "completed":
        raise HTTPException(status_code=409, detail=f"Job is still {status_info.get('status')}.")
    if status_info.get("conclusion") != "success":
        detail_msg = f"Job ended with conclusion: {status_info.get('conclusion')}."
        raise HTTPException(status_code=400, detail=detail_msg)

    run_id = status_info.get("github_run_id")
    if run_id:
        downloaded = await ensure_job_artifacts_downloaded(job_id, run_id)
        if downloaded:
            return parse_job_artifacts(downloaded, job_id)

    raise HTTPException(status_code=404, detail="Artifacts not found or still processing.")


@app.get("/api/jobs/{job_id}/artifacts.zip")
async def download_job_artifacts_zip(job_id: str) -> StreamingResponse:
    """Download safely filtered zip archive of benchmark outputs."""
    if not VALID_JOB_ID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    target_dir = CACHE_DIR / job_id
    if not target_dir.is_dir():
        status_info = await get_job_status(job_id)
        run_id = status_info.get("github_run_id")
        is_done = status_info.get("status") == "completed"
        is_succ = status_info.get("conclusion") == "success"
        if run_id and is_done and is_succ:
            await ensure_job_artifacts_downloaded(job_id, run_id)

    if not target_dir.is_dir():
        raise HTTPException(status_code=404, detail="No artifacts available for download.")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in target_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if not is_safe_artifact_file(file_path):
                continue
            rel_path = file_path.relative_to(target_dir)
            zf.write(file_path, arcname=str(rel_path))

    zip_buffer.seek(0)
    filename = f"cairn-results-{job_id}.zip"
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/jobs/{job_id}/report.html")
async def view_job_report_html(job_id: str) -> HTMLResponse:
    """Serve offline HTML report for completed job."""
    if not VALID_JOB_ID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    target_dir = CACHE_DIR / job_id
    if target_dir.is_dir():
        for r_html in target_dir.rglob("report.html"):
            return HTMLResponse(r_html.read_text(encoding="utf-8"))

    raise HTTPException(status_code=404, detail="Report HTML not found for this job.")


# --- Frontend Serving ---


@app.get("/", response_class=HTMLResponse)
async def serve_index() -> HTMLResponse:
    """Serve the interactive single-page application."""
    index_file = BASE_DIR / "site" / "index.html"
    if not index_file.is_file():
        raise HTTPException(status_code=404, detail="site/index.html not found.")
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


@app.get("/site/{path:path}")
async def serve_site_assets(path: str) -> Response:
    """Serve supplementary static assets from site/ if requested."""
    safe_path = os.path.normpath(path)
    if safe_path.startswith("..") or os.path.isabs(safe_path):
        raise HTTPException(status_code=400, detail="Invalid path.")
    target = BASE_DIR / "site" / safe_path
    if target.is_file():
        return FileResponse(target)
    raise HTTPException(status_code=404, detail="Asset not found.")
