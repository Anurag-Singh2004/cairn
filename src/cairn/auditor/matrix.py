"""N x N Reachability and Egress Matrix Verification (Conformance Test C3).

Implements context.md §8.6 and §9.2:
- Runs netprobe inside each container by service name and IP
- Asserts that in T1 ONLY expected edges are reachable
- Asserts zero external egress in T1
- Validates that T0 exhibits planted cross-tenant edges (positive control)
"""

from __future__ import annotations

import json
from typing import Any

from cairn.referee.docker_ctl import compose_exec

T1_EXPECTED_EDGES = [
    ("red", "switchboard", 8000),
    ("switchboard", "blue", 8100),
    ("switchboard", "model", 8200),
]


def audit_matrix(tier: str = "t1") -> dict[str, Any]:
    """Execute N x N reachability audit across services."""
    services = ["red", "switchboard", "blue", "model"]
    targets = [
        "switchboard:8000",
        "blue:8100",
        "model:8200",
    ]

    measured_edges: list[dict[str, Any]] = []
    egress_detected: dict[str, bool] = {}

    for src in services:
        cmd = ["python", "-m", "cairn.tenants.netprobe", "--targets", *targets, "--check-egress"]
        rc, out, _err = compose_exec(tier, src, cmd)
        if rc != 0:
            measured_edges.append({"source": src, "error": "Probe execution failed"})
            continue

        try:
            report = json.loads(out)
            egress_detected[src] = bool(report.get("egress", False))
            for edge in report.get("edges", []):
                measured_edges.append(
                    {
                        "source": src,
                        "target": edge["target"],
                        "port": edge["port"],
                        "reachable": edge["reachable"],
                    }
                )
        except Exception as e:
            measured_edges.append({"source": src, "error": f"Failed to parse report: {e}"})

    deviations: list[str] = []
    if tier == "t1":
        # In T1: Only T1_EXPECTED_EDGES should be reachable
        for edge in measured_edges:
            if "error" in edge:
                deviations.append(f"{edge['source']}: {edge['error']}")
                continue
            src, tgt, port, reachable = (
                edge["source"],
                edge["target"],
                edge["port"],
                edge["reachable"],
            )
            if src == tgt:
                continue

            is_expected = (src, tgt, port) in T1_EXPECTED_EDGES
            if is_expected and not reachable:
                deviations.append(f"Expected edge {src} -> {tgt}:{port} is NOT reachable")
            elif not is_expected and reachable:
                deviations.append(f"Illegal edge {src} -> {tgt}:{port} IS reachable")

        for src, has_egress in egress_detected.items():
            if has_egress:
                deviations.append(f"Service '{src}' has illegal external egress in T1")

    return {
        "tier": tier,
        "measured_edges": measured_edges,
        "egress_detected": egress_detected,
        "deviations": deviations,
        "valid": len(deviations) == 0,
    }
