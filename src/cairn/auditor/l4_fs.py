"""L4 Filesystem, Shared-Volume, and Environment Enumeration Probe.

Implements context.md §9.3 and flow.md §5 M4:
- Enumerates reachable filesystem paths, shared volumes (/shared), and environment variables
- Detects foreign tenant canaries (canary_*) or planted misconfigurations
- On T0 positive control: shared volume leak detected (status: LEAK_DETECTED)
- On T1 hardened tier: no shared volume, no foreign canaries (status: NO_SIGNAL_AT_POWER)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from cairn.switchboard.pipeline import SwitchboardPipeline

CANARY_PATTERN = re.compile(r"canary_[a-zA-Z0-9_]+")


class L4FsProbe:
    """Auditor probe evaluating filesystem, shared volume, and environment isolation."""

    def __init__(
        self,
        shared_dir: Path | str = "/shared",
        scan_paths: list[Path | str] | None = None,
        registered_canaries: list[str] | None = None,
    ) -> None:
        self.shared_dir = Path(shared_dir)
        self.scan_paths = [Path(p) for p in scan_paths] if scan_paths else [self.shared_dir]
        self.registered_canaries = set(registered_canaries or [])

    def run_probe(
        self,
        pipeline: SwitchboardPipeline | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Execute L4 enumeration probe."""
        foreign_canaries: list[str] = []
        scanned_paths: list[str] = []
        shared_volume_present = self.shared_dir.is_dir()
        details_list: list[str] = []

        # 1. Scan shared volumes and configured paths
        for path in self.scan_paths:
            if not path.is_dir():
                continue
            scanned_paths.append(str(path))
            try:
                for p in path.rglob("*"):
                    if p.is_file():
                        try:
                            content = p.read_text(encoding="utf-8", errors="replace")
                            matches = CANARY_PATTERN.findall(content)
                            for m in matches:
                                if m not in self.registered_canaries:
                                    foreign_canaries.append(f"file:{p.name}:{m}")
                                    details_list.append(f"Found foreign canary {m} in {p}")
                            if "PLANTED_MISCONFIG" in content:
                                details_list.append(f"Found planted misconfiguration in {p}")
                        except Exception as e:
                            details_list.append(f"Could not read {p}: {e}")
            except Exception as e:
                details_list.append(f"Could not scan directory {path}: {e}")

        # 2. Scan environment variables
        for k, v in os.environ.items():
            matches = CANARY_PATTERN.findall(v)
            for m in matches:
                if m not in self.registered_canaries:
                    foreign_canaries.append(f"env:{k}:{m}")
                    details_list.append(f"Found foreign canary {m} in environment variable {k}")

        leak_detected = len(foreign_canaries) > 0 or (
            shared_volume_present and any("PLANTED_MISCONFIG" in d for d in details_list)
        )
        status = "LEAK_DETECTED" if leak_detected else "NO_SIGNAL_AT_POWER"

        report = {
            "probe": "L4",
            "status": status,
            "leak_detected": leak_detected,
            "canaries_found": foreign_canaries,
            "paths_scanned": scanned_paths,
            "shared_volume_present": shared_volume_present,
            "details": (
                "; ".join(details_list)
                if details_list
                else "No leaks detected in storage or environment"
            ),
        }

        if pipeline is not None:
            pipeline.emit_event("probe.l4.result", report)

        return report
