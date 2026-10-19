"""Receipt generation per context.md §8.7.

A receipt is a self-contained proof file for one finding containing:
- manifest & commitments
- finding-scoped and run-level evidence events
- RFC 6962 inclusion proofs for each event to checkpoint.root
- signed checkpoint and referee public key
- evaluated validity certificate
"""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from cairn.common.schemas import Checkpoint, Event, Receipt
from cairn.crypto.merkle import compute_inclusion_proof_hex
from cairn.referee.evidence import EvidenceStore
from cairn.referee.validity import evaluate_certificate

RUN_LEVEL_EVENT_KINDS = {
    "run.created",
    "manifest.frozen",
    "preflight.report",
    "attestation.manifest",
    "attestation.matrix",
    "attestation.canary_scan",
    "probe.l1.result",
    "probe.l3.result",
    "probe.l4.result",
    "reveal.verification",
    "run.concluded",
    "violation.succeeded",
    "violation.denied",
}


def filter_receipt_events(all_events: list[Event], finding: str) -> list[Event]:
    """Filter run events to include run-level evidence plus finding-scoped events."""
    included: list[Event] = []
    for ev in all_events:
        ev_finding = ev.body.get("finding")
        if ev_finding == finding or (not ev_finding and ev.kind in RUN_LEVEL_EVENT_KINDS):
            included.append(ev)
    included.sort(key=lambda e: e.seq)
    return included


def generate_finding_receipt(
    finding: str,
    all_events: list[Event],
    checkpoint: Checkpoint,
    signature: str,
    public_key_b64: str,
    manifest: dict[str, Any],
    commitments: dict[str, Any],
    tool_versions: dict[str, str] | None = None,
) -> Receipt:
    """Generate a self-contained receipt for a single finding."""
    leaves_bytes = [bytes.fromhex(ev.hash) for ev in all_events]
    seq_to_index = {ev.seq: idx for idx, ev in enumerate(all_events)}

    receipt_events = filter_receipt_events(all_events, finding)

    proofs: list[dict[str, Any]] = []
    for ev in receipt_events:
        leaf_idx = seq_to_index[ev.seq]
        path_hex = compute_inclusion_proof_hex(leaf_idx, leaves_bytes)
        proofs.append(
            {
                "index": leaf_idx,
                "leaf_hash": ev.hash,
                "path": path_hex,
            }
        )

    cert = evaluate_certificate(
        events=receipt_events,
        finding=finding,
        manifest=manifest,
    )

    tools = tool_versions or {
        "cairn": "0.1.0",
        "python": platform.python_version(),
    }

    return Receipt(
        receipt_version=1,
        run=checkpoint.run,
        finding=finding,
        manifest=manifest,
        commitments=commitments,
        events=[ev.model_dump() for ev in receipt_events],
        proofs=proofs,
        checkpoint=checkpoint.canonical_dict(),
        signature=signature,
        certificate=cert.model_dump(),
        tool_versions=tools,
        key_id=checkpoint.key_id,
        pubkey_b64=public_key_b64,
    )


def save_receipt_file(receipt: Receipt | dict[str, Any], path: Path | str) -> Path:
    """Save receipt object or dictionary as formatted JSON."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = receipt.model_dump() if hasattr(receipt, "model_dump") else receipt
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return out_path


def generate_all_receipts_for_run(
    store: EvidenceStore,
    checkpoint: Checkpoint,
    signature: str,
    public_key_b64: str,
    manifest: dict[str, Any],
    commitments: dict[str, Any],
    out_dir: Path | str,
    target_findings: set[str] | list[str] | None = None,
) -> dict[str, Receipt]:
    """Generate and write receipts for all findings in a completed run."""
    all_events = store.get_events()
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    findings: set[str] = set()
    if target_findings is not None:
        findings = set(target_findings)
    else:
        for ev in all_events:
            f = ev.body.get("finding")
            if f and not f.startswith("f_l") and f != "f_000":
                findings.add(f)

    receipts: dict[str, Receipt] = {}
    for finding in sorted(findings):
        receipt = generate_finding_receipt(
            finding=finding,
            all_events=all_events,
            checkpoint=checkpoint,
            signature=signature,
            public_key_b64=public_key_b64,
            manifest=manifest,
            commitments=commitments,
        )
        receipt_file = out_path / f"receipt_{finding}.json"
        save_receipt_file(receipt, receipt_file)
        receipts[finding] = receipt

    return receipts
