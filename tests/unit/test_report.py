"""Unit test for offline HTML report generation."""

from __future__ import annotations

from pathlib import Path

from cairn.referee.evidence import EvidenceStore
from cairn.referee.report import generate_html_report


def test_html_report_generation(tmp_path: Path):
    db_path = tmp_path / "evidence.db"
    store = EvidenceStore(db_path)
    run_id = "r_report_test_01"

    manifest = {
        "run": run_id,
        "tier": "t1",
        "compose_sha256": "compose123",
        "images": {"switchboard": "img1", "blue": "img2", "model": "img3"},
        "cache_isolation": "salted",
        "model": {"backend": "sim_engine"},
    }

    store.append_event(run_id, 1000, "run.created", "referee", {"tier": "t1"})
    store.append_event(run_id, 2000, "manifest.frozen", "referee", manifest)
    store.append_event(
        run_id,
        3000,
        "attestation.matrix",
        "auditor",
        {"phase": "pre", "deviations": 0, "observed_edges": []},
    )

    # Finding f_001
    store.append_event(
        run_id, 4000, "request.received", "switchboard", {"finding": "f_001", "session_id": "s1"}
    )
    store.append_event(
        run_id,
        5000,
        "blue.input.verdict",
        "blue",
        {"finding": "f_001", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        6000,
        "model.call",
        "switchboard",
        {
            "finding": "f_001",
            "session_id": "s1",
            "namespace_id": "ns1",
            "cache_isolation": "salted",
            "simulated": True,
        },
    )
    store.append_event(
        run_id,
        7000,
        "blue.output.verdict",
        "blue",
        {"finding": "f_001", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        8000,
        "response.released",
        "switchboard",
        {"finding": "f_001", "bucket": 256, "flag_hit": False, "proc_ms": 100, "release_ms": 250},
    )

    store.append_event(
        run_id, 9000, "probe.l1.result", "auditor", {"status": "NO_SIGNAL_AT_POWER", "trials": 200}
    )
    store.append_event(
        run_id, 10000, "probe.l4.result", "auditor", {"status": "NO_SIGNAL", "canaries_found": 0}
    )
    store.append_event(
        run_id, 11000, "attestation.canary_scan", "auditor", {"canaries_found": 0, "leaks": []}
    )
    store.append_event(
        run_id,
        12000,
        "attestation.matrix",
        "auditor",
        {"phase": "post", "deviations": 0, "observed_edges": []},
    )
    store.append_event(
        run_id,
        13000,
        "attestation.manifest",
        "auditor",
        {"compose_sha256": "compose123", "images": manifest["images"]},
    )
    store.append_event(
        run_id,
        14000,
        "reveal.verification",
        "referee",
        {"verified": True, "red_verified": True, "blue_verified": True},
    )
    store.append_event(run_id, 15000, "run.concluded", "referee", {"status": "complete"})

    out_html = tmp_path / "report.html"
    report_file = generate_html_report(run_id=run_id, store=store, out_path=out_html)

    assert report_file.is_file()
    content = report_file.read_text(encoding="utf-8")

    # Check key requirements: offline, self-contained, tier badge,
    # invariants, probes, SIMULATED label, residual risk
    assert "<html" in content
    assert "CAIRN Assurance Report" in content
    assert "T1 TIER" in content
    assert "SIMULATED" in content
    assert "f_001" in content
    assert "L1 Prefix-Cache Timing" in content
    assert "Residual-Risk Register" in content
    assert (
        "http://" not in content and "https://" not in content
    )  # Zero external assets / fully offline
