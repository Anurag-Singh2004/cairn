"""Fault injection and environmental stress engine per context.md §8.2/§8.5 and flow.md §5 M6.

Supports:
- Fault injection: `--inject-fault <fault_type>@<finding_id>`
  e.g. `blue_timeout@f_005`, `blue_error@f_003`, `model_error@f_002`
- CPU burn: `--burn` consumes CPU cycles to simulate noisy-neighbor environmental interference
- Labels injected events with `injected: true` per flow.md §5 M6
"""

from __future__ import annotations

import multiprocessing
from typing import Any


class FaultInjector:
    """Manages active fault injection rules for a benchmark run."""

    def __init__(self, fault_specs: list[str] | None = None) -> None:
        self.faults: dict[str, str] = {}  # {finding_id: fault_type}
        if fault_specs:
            for spec in fault_specs:
                if "@" in spec:
                    fault_type, finding = spec.split("@", 1)
                    self.faults[finding.strip()] = fault_type.strip()

    def get_fault_for_finding(self, finding: str) -> str | None:
        """Return injected fault type for finding, if any."""
        return self.faults.get(finding)

    def should_inject_fault(self, fault_type: str, finding: str) -> bool:
        """Check if specific fault should be injected for finding."""
        return self.faults.get(finding) == fault_type


def _cpu_burner_worker(stop_event: multiprocessing.Event) -> None:
    """Burn CPU cycles continuously until stop_event is set."""
    val = 0
    while not stop_event.is_set():
        val = (val * 1103515245 + 12345) & 0x7FFFFFFF


class CpuBurner:
    """Background CPU burner to simulate resource contention."""

    def __init__(self, num_workers: int = 2) -> None:
        self.num_workers = max(1, num_workers)
        self.stop_event = multiprocessing.Event()
        self.processes: list[multiprocessing.Process] = []

    def start(self) -> None:
        self.stop_event.clear()
        for _ in range(self.num_workers):
            p = multiprocessing.Process(
                target=_cpu_burner_worker,
                args=(self.stop_event,),
                daemon=True,
            )
            p.start()
            self.processes.append(p)

    def stop(self) -> None:
        self.stop_event.set()
        for p in self.processes:
            p.join(timeout=1.0)
            if p.is_alive():
                p.terminate()
        self.processes.clear()


def simulate_fault_effect(
    tier: str,
    fault_type: str,
    finding: str,
) -> dict[str, Any]:
    """Calculate the outcome of a fault in T0 (fail-open) vs T1 (fail-closed).

    In T0:
      Faults cause fail-open bypass -> uninspected payload reaches model,
      generating a false BYPASS, recorded as infra.failopen / infra.timeout.
    In T1:
      Faults fail closed -> Switchboard emits generic refusal envelope,
      records infra.timeout / infra.error, verdict is BLOCKED.
    """
    if tier == "t0":
        # Fail-open positive control
        return {
            "verdict": "BYPASS",
            "fail_open": True,
            "blocked": False,
            "event_kind": "infra.failopen" if "timeout" not in fault_type else "infra.timeout",
            "body": {
                "finding": finding,
                "fault": fault_type,
                "injected": True,
                "tier": "t0",
                "semantics": "fail_open",
            },
        }
    else:
        # T1 hardened fail-closed
        return {
            "verdict": "BLOCKED",
            "fail_open": False,
            "blocked": True,
            "event_kind": "infra.timeout" if "timeout" in fault_type else "infra.error",
            "body": {
                "finding": finding,
                "fault": fault_type,
                "injected": True,
                "tier": "t1",
                "semantics": "fail_closed",
            },
        }
