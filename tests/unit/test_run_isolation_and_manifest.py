"""Regression tests for run isolation, manifest resolution, and atomic receipts.

Validates fixes for:
1. Explicit current manifest not replaced by stale historical event.
2. Stale manifest and attestation events in event streams do not cause false quarantining.
3. run_benchmark raises EvidenceError upon run-ID collision.
4. Demo run ID generation strategy generates fresh unique IDs when demo runs exist.
5. Atomic receipt file writing succeeds and cleans up temporary files upon failure.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cairn.cli import select_demo_run_ids
from cairn.common.errors import EvidenceError
from cairn.common.schemas import Event
from cairn.referee.receipts import save_receipt_file
from cairn.referee.runner import run_benchmark
from cairn.referee.validity import evaluate_certificate


def test_explicit_manifest_not_overwritten_by_stale_event() -> None:
    """An explicit current manifest must not be replaced by a stale manifest.frozen event."""
    stale_event = Event(
        seq=1,
        run="r_test",
        ts_ns=1000,
        kind="manifest.frozen",
        actor="referee",
        body={
            "run": "r_test",
            "compose_sha256": "f1e2d3c4b5a6",  # Stale placeholder
            "images": {"switchboard": "sha256:stale:latest"},
        },
        prev="0" * 64,
        hash="h1",
    )
    current_attestation = Event(
        seq=2,
        run="r_test",
        ts_ns=2000,
        kind="attestation.manifest",
        actor="auditor",
        body={
            "compose_sha256": "real_valid_compose_sha_9999",
            "images": {"switchboard": "sha256:real_valid_image_9999"},
        },
        prev="h1",
        hash="h2",
    )
    explicit_manifest = {
        "run": "r_test",
        "compose_sha256": "real_valid_compose_sha_9999",
        "images": {"switchboard": "sha256:real_valid_image_9999"},
    }

    # Evaluate certificate with explicit manifest
    cert = evaluate_certificate(
        events=[stale_event, current_attestation],
        manifest=explicit_manifest,
    )
    # I1 must pass because the explicit manifest matches the attestation
    assert cert.invariants["I1"].result == "pass"
    assert cert.invariants["I1"].reason_code == "MANIFEST_INTEGRITY_VERIFIED"


def test_stale_manifest_and_attestation_events_dont_quarantine_matching_run() -> None:
    """When resolving from events, attestation and manifest must correspond to the run."""
    compose_hash = "5ccab640c0715e61771ab8794c01206fa853f49f5c45539e3cf4e1fb4190790c"
    img_digest = "sha256:fba1ea87c8f83e8b38f252760efd8cf0d904b5e681615b161467e29562f9cb3c"

    events = [
        # Run 1 events (historical run with placeholder)
        Event(
            seq=1,
            run="r_demo_t1",
            ts_ns=1000,
            kind="manifest.frozen",
            actor="referee",
            body={
                "run": "r_demo_t1",
                "compose_sha256": "f1e2d3c4b5a6",
                "images": {"switchboard": "sha256:switchboard:latest"},
            },
            prev="0" * 64,
            hash="h1",
        ),
        Event(
            seq=2,
            run="r_demo_t1",
            ts_ns=2000,
            kind="attestation.manifest",
            actor="auditor",
            body={
                "compose_sha256": "f1e2d3c4b5a6",
                "images": {"switchboard": "sha256:switchboard:latest"},
            },
            prev="h1",
            hash="h2",
        ),
        # Run 2 events (fresh run with valid identifiers)
        Event(
            seq=3,
            run="r_demo_t1",
            ts_ns=3000,
            kind="manifest.frozen",
            actor="referee",
            body={
                "run": "r_demo_t1",
                "compose_sha256": compose_hash,
                "images": {"switchboard": img_digest},
            },
            prev="h2",
            hash="h3",
        ),
        Event(
            seq=4,
            run="r_demo_t1",
            ts_ns=4000,
            kind="attestation.manifest",
            actor="auditor",
            body={
                "compose_sha256": compose_hash,
                "images": {"switchboard": img_digest},
            },
            prev="h3",
            hash="h4",
        ),
    ]

    # Evaluate certificate without explicit manifest: resolves latest valid events in reverse
    cert = evaluate_certificate(events=events, manifest=None)
    assert cert.invariants["I1"].result == "pass"
    assert cert.invariants["I1"].reason_code == "MANIFEST_INTEGRITY_VERIFIED"


def test_run_benchmark_collision_raises_evidence_error(tmp_path: Path) -> None:
    """run_benchmark fails closed with EvidenceError if target run DB already exists."""
    run_id = "r_test_collision"
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    db_file = run_dir / "evidence.db"
    db_file.write_text("existing sqlite header", encoding="utf-8")

    dummy_pack = tmp_path / "dummy_pack.json"
    dummy_pack.write_text(json.dumps({"attacks": []}), encoding="utf-8")
    dummy_policy = tmp_path / "dummy_policy.json"
    dummy_policy.write_text(json.dumps({"input_rules": [], "output_rules": []}), encoding="utf-8")

    with pytest.raises(EvidenceError) as exc_info:
        run_benchmark(
            tier="t1",
            pack_path=dummy_pack,
            policy_path=dummy_policy,
            run_id=run_id,
            runs_root=tmp_path,
        )

    assert f"Run ID '{run_id}' already exists" in str(exc_info.value)
    assert "cannot be overwritten or silently appended to" in str(exc_info.value)


def test_save_receipt_file_atomic_success(tmp_path: Path) -> None:
    """save_receipt_file writes formatted JSON atomically without leaving temp files."""
    receipt_data = {"receipt_version": 1, "finding": "f_001", "status": "VALID"}
    target_path = tmp_path / "receipt_f_001.json"

    saved_path = save_receipt_file(receipt_data, target_path)
    assert saved_path == target_path
    assert target_path.is_file()

    # Verify content
    loaded = json.loads(target_path.read_text(encoding="utf-8"))
    assert loaded["finding"] == "f_001"

    # Verify no temporary files remain in directory
    tmp_files = list(tmp_path.glob(".*tmp*"))
    assert len(tmp_files) == 0


def test_save_receipt_file_cleanup_on_failure(tmp_path: Path) -> None:
    """save_receipt_file must clean up its temporary file if atomic replace fails."""
    receipt_data = {"receipt_version": 1, "finding": "f_002"}
    target_path = tmp_path / "receipt_f_002.json"

    with (
        patch("os.replace", side_effect=OSError("Simulated replace disk failure")),
        pytest.raises(OSError, match="Simulated replace disk failure"),
    ):
        save_receipt_file(receipt_data, target_path)

    # Ensure target file was not created
    assert not target_path.exists()

    # Ensure any temporary file was cleaned up
    tmp_files = list(tmp_path.glob(".*tmp*"))
    assert len(tmp_files) == 0


def test_select_demo_run_ids_preserves_existing_runs_and_yields_distinct_ids(
    tmp_path: Path,
) -> None:
    """Repeated demo invocation preserves existing evidence and produces distinct IDs."""
    # First invocation: clean root -> default run IDs
    t0_1, t1_1, fault_1 = select_demo_run_ids(tmp_path)
    assert t0_1 == "r_demo_t0"
    assert t1_1 == "r_demo_t1"
    assert fault_1 == "r_demo_fault"

    # Simulate existing evidence databases in those directories
    for run_id in (t0_1, t1_1, fault_1):
        db_path = tmp_path / run_id / "evidence.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.write_text(f"historical_evidence_for_{run_id}", encoding="utf-8")

    # Second invocation: existing runs present -> returns distinct timestamped IDs
    t0_2, t1_2, fault_2 = select_demo_run_ids(tmp_path)
    assert t0_2 != t0_1
    assert t1_2 != t1_1
    assert fault_2 != fault_1
    assert t0_2.startswith("r_demo_t0_")
    assert t1_2.startswith("r_demo_t1_")
    assert fault_2.startswith("r_demo_fault_")

    # Verify original historical evidence files are untouched and preserved
    assert (tmp_path / t0_1 / "evidence.db").read_text(
        encoding="utf-8"
    ) == f"historical_evidence_for_{t0_1}"
    assert (tmp_path / t1_1 / "evidence.db").read_text(
        encoding="utf-8"
    ) == f"historical_evidence_for_{t1_1}"
    assert (tmp_path / fault_1 / "evidence.db").read_text(
        encoding="utf-8"
    ) == f"historical_evidence_for_{fault_1}"

    # Simulate immediate collision on t0_2 to verify counter suffix works
    (tmp_path / t0_2 / "evidence.db").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / t0_2 / "evidence.db").write_text("second_run_data", encoding="utf-8")

    t0_3, _, _ = select_demo_run_ids(tmp_path)
    assert t0_3 != t0_1
    assert t0_3 != t0_2
    assert not (tmp_path / t0_3 / "evidence.db").exists()
