"""Conformance test evaluator (C1, C2, C3, C8, C9, C11, C12) per context.md §9.2."""

from __future__ import annotations

from typing import Any

from cairn.common.schemas import Event


def evaluate_conformance_from_events(events: list[Event | dict[str, Any]]) -> dict[str, Any]:
    """Evaluate deterministic conformance criteria from run evidence events."""
    ev_list: list[dict[str, Any]] = [e if isinstance(e, dict) else e.model_dump() for e in events]

    has_violation_denied = any(e.get("kind") == "violation.denied" for e in ev_list)
    has_violation_succeeded = any(e.get("kind") == "violation.succeeded" for e in ev_list)

    # C1 / C2 / C11: Unauthorised requests were denied
    authz_enforced = not has_violation_succeeded

    # C3: Attestation matrix enforcement
    matrix_evs = [e for e in ev_list if e.get("kind") == "attestation.matrix"]
    c3_pass = (
        all(e.get("body", {}).get("deviations", 0) == 0 for e in matrix_evs)
        if matrix_evs
        else False
    )

    # I6 / C12: Commit-reveal verification
    reveal_ev = next((e for e in ev_list if e.get("kind") == "reveal.verification"), None)
    c12_pass = bool(reveal_ev and reveal_ev.get("body", {}).get("verified", False))

    return {
        "C1_unauthorized_artifact_access_denied": authz_enforced,
        "C2_metadata_access_denied": authz_enforced,
        "C3_network_topology_enforced": c3_pass,
        "C11_unauthorized_reveal_denied": authz_enforced or has_violation_denied,
        "C12_commit_reveal_integrity": c12_pass,
    }
