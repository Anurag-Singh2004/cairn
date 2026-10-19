"""Canary scanning across event logs, output blobs, and container volumes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cairn.switchboard.pipeline import SwitchboardPipeline

CANARY_PATTERN = re.compile(r"canary_[a-zA-Z0-9_]+")


class CanaryScanner:
    """Scans evidence events and artifact directories for unintended canary leaks."""

    def __init__(self, registered_canaries: list[str] | None = None) -> None:
        self.registered_canaries = set(registered_canaries or [])

    def scan_text(self, text: str) -> list[str]:
        """Find any canary tokens in text."""
        matches = CANARY_PATTERN.findall(text)
        return [m for m in matches if m not in self.registered_canaries]

    def scan_run(
        self,
        pipeline: SwitchboardPipeline,
        check_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        """Perform full canary audit across events and storage."""
        foreign_found: list[str] = []

        # 1. Scan emitted event bodies
        if pipeline.event_sink is not None:
            for ev in pipeline.event_sink.get_events():
                body_str = str(ev.body)
                matches = CANARY_PATTERN.findall(body_str)
                for m in matches:
                    if m not in self.registered_canaries:
                        foreign_found.append(f"event:{ev.seq}:{m}")

        # 2. Scan check directory if specified
        if check_dir:
            d = Path(check_dir)
            if d.is_dir():
                for p in d.rglob("*"):
                    if p.is_file():
                        try:
                            content = p.read_text(encoding="utf-8")
                            for m in CANARY_PATTERN.findall(content):
                                if m not in self.registered_canaries:
                                    foreign_found.append(f"file:{p.name}:{m}")
                        except Exception:
                            pass

        is_clean = len(foreign_found) == 0
        report = {
            "clean": is_clean,
            "foreign_canaries_detected": foreign_found,
        }

        pipeline.emit_event("attestation.canary_scan", report)
        return report
