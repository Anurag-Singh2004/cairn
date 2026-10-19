"""Unit tests for referee validity engine and invariants I1 through I9.

Tests table-driven pass/fail/warn/missing conditions and DEC-16 precedence.
"""

from __future__ import annotations

from cairn.common.schemas import Event
from cairn.referee.validity import evaluate_certificate


def _make_event(
    seq: int,
    kind: str,
    body: dict,
    actor: str = "switchboard",
    run: str = "r_test_001",
    ts_ns: int = 1760000000000000000,
    prev: str = "0000000000000000000000000000000000000000000000000000000000000000",
) -> Event:
    ev_hash = Event.compute_hash(
        seq=seq,
        run=run,
        ts_ns=ts_ns,
        kind=kind,
        actor=actor,
        body=body,
        prev=prev,
    )
    return Event(
        seq=seq,
        run=run,
        ts_ns=ts_ns,
        kind=kind,
        actor=actor,
        body=body,
        prev=prev,
        hash=ev_hash,
    )


def _recompute_hashes(events: list[Event]) -> list[Event]:
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    for ev in events:
        ev.prev = prev_hash
        ev.hash = Event.compute_hash(
            seq=ev.seq,
            run=ev.run,
            ts_ns=ev.ts_ns,
            kind=ev.kind,
            actor=ev.actor,
            body=ev.body,
            prev=prev_hash,
        )
        prev_hash = ev.hash
    return events


def _build_clean_event_stream(
    finding: str = "f_001",
    simulated: bool = True,
    cache_isolation: str = "salted",
) -> list[Event]:
    events: list[Event] = []
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    def add(kind: str, body: dict, actor: str = "switchboard") -> None:
        nonlocal prev_hash
        seq = len(events) + 1
        ev = _make_event(
            seq=seq,
            kind=kind,
            body=body,
            actor=actor,
            prev=prev_hash,
        )
        events.append(ev)
        prev_hash = ev.hash

    # Lifecycle & Manifest
    add("run.created", {"tier": "t1"}, actor="referee")
    add(
        "manifest.frozen",
        {
            "compose_sha256": "compose_hash_abc",
            "images": {"switchboard": "img_sb", "blue": "img_blue", "model": "img_model"},
            "cache_isolation": cache_isolation,
        },
        actor="referee",
    )
    add(
        "attestation.matrix",
        {"phase": "pre", "deviations": 0, "observed_edges": []},
        actor="auditor",
    )

    # Scored finding
    add("request.received", {"finding": finding, "session_id": "sess_1"}, actor="switchboard")
    add(
        "blue.input.verdict",
        {"finding": finding, "verdict": "allow", "reason": "R_NONE"},
        actor="blue",
    )
    add(
        "model.call",
        {
            "finding": finding,
            "session_id": "sess_1",
            "namespace_id": "ns_sess_1",
            "cache_isolation": cache_isolation,
            "simulated": simulated,
            "finish_reason": "stop",
        },
        actor="switchboard",
    )
    add(
        "blue.output.verdict",
        {"finding": finding, "verdict": "allow", "reason": "R_NONE"},
        actor="blue",
    )
    add(
        "response.released",
        {
            "finding": finding,
            "bucket": 256,
            "flag_hit": False,
            "proc_ms": 120,
            "release_ms": 250,
        },
        actor="switchboard",
    )

    # Audits & Attestations
    add("probe.l1.result", {"status": "NO_SIGNAL_AT_POWER", "trials": 200}, actor="auditor")
    add("probe.l4.result", {"status": "NO_SIGNAL", "canaries_found": 0}, actor="auditor")
    add("attestation.canary_scan", {"canaries_found": 0, "leaks": []}, actor="auditor")
    add(
        "attestation.matrix",
        {"phase": "post", "deviations": 0, "observed_edges": []},
        actor="auditor",
    )
    add(
        "attestation.manifest",
        {
            "compose_sha256": "compose_hash_abc",
            "images": {"switchboard": "img_sb", "blue": "img_blue", "model": "img_model"},
        },
        actor="auditor",
    )
    add(
        "reveal.verification",
        {"verified": True, "red_verified": True, "blue_verified": True},
        actor="referee",
    )
    add("run.concluded", {"status": "complete"}, actor="referee")

    return events


def test_clean_t1_run_simulated_yields_valid_with_warnings():
    events = _build_clean_event_stream(finding="f_001", simulated=True)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "VALID_WITH_WARNINGS"
    assert cert.simulated is True
    assert cert.invariants["I1"].result == "pass"
    assert cert.invariants["I2"].result == "pass"
    assert cert.invariants["I3"].result == "pass"
    assert cert.invariants["I4"].result == "pass"
    assert cert.invariants["I5"].result == "pass"
    assert cert.invariants["I6"].result == "pass"
    assert cert.invariants["I7"].result == "pass"
    assert cert.invariants["I8"].result == "pass"
    assert cert.invariants["I9"].result == "pass"


def test_clean_t1_run_non_simulated_yields_valid():
    events = _build_clean_event_stream(finding="f_001", simulated=False)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "VALID"
    assert cert.simulated is False


def test_i1_manifest_tamper_fails():
    events = _build_clean_event_stream()
    # Tamper attestation.manifest
    for ev in events:
        if ev.kind == "attestation.manifest":
            ev.body["compose_sha256"] = "tampered_compose_hash"
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I1"].result == "fail"
    assert "MISMATCH" in cert.invariants["I1"].reason_code


def test_i2_matrix_deviations_fail():
    events = _build_clean_event_stream()
    for ev in events:
        if ev.kind == "attestation.matrix" and ev.body.get("phase") == "post":
            ev.body["deviations"] = 2
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I2"].result == "fail"
    assert "DEVIATION" in cert.invariants["I2"].reason_code


def test_i3_canary_leak_fails():
    events = _build_clean_event_stream()
    for ev in events:
        if ev.kind == "attestation.canary_scan":
            ev.body["canaries_found"] = 1
            ev.body["leaks"] = ["canary_red_123 found in blue"]
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I3"].result == "fail"


def test_i4_l1_leak_detected_fails():
    events = _build_clean_event_stream()
    for ev in events:
        if ev.kind == "probe.l1.result":
            ev.body["status"] = "LEAK_DETECTED"
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I4"].result == "fail"


def test_i4_inconclusive_warns():
    events = _build_clean_event_stream(simulated=False)
    for ev in events:
        if ev.kind == "probe.l1.result":
            ev.body["status"] = "INCONCLUSIVE"
    _recompute_hashes(events)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "VALID_WITH_WARNINGS"
    assert cert.invariants["I4"].result == "warn"


def test_i5_and_i9_timeout_fails():
    events = _build_clean_event_stream()
    # Add an infra.timeout event for finding f_001
    last = events[-1]
    timeout_ev = _make_event(
        seq=len(events) + 1,
        kind="infra.timeout",
        body={"finding": "f_001", "stage": "model_call"},
        actor="switchboard",
        prev=last.hash,
    )
    events.append(timeout_ev)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I5"].result == "fail"
    assert cert.invariants["I9"].result == "fail"


def test_i6_reveal_failure_fails():
    events = _build_clean_event_stream()
    for ev in events:
        if ev.kind == "reveal.verification":
            ev.body["verified"] = False
    _recompute_hashes(events)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I6"].result == "fail"


def test_i7_hash_tamper_fails():
    events = _build_clean_event_stream()
    # Mutate event body without recomputing hash
    events[3].body["verdict"] = "tampered_verdict"
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I7"].result == "fail"


def test_i8_violation_succeeded_fails():
    events = _build_clean_event_stream()
    last = events[-1]
    viol_ev = _make_event(
        seq=len(events) + 1,
        kind="violation.succeeded",
        body={"actor": "red", "target": "blue_policy"},
        actor="switchboard",
        prev=last.hash,
    )
    events.append(viol_ev)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I8"].result == "fail"


def test_incomplete_run_when_mid_run_abort():
    # Only events up to request.received (model was killed mid-run)
    clean = _build_clean_event_stream(finding="f_001")
    aborted_events = clean[
        :4
    ]  # only run.created, manifest.frozen, attestation.matrix, request.received
    cert = evaluate_certificate(aborted_events, finding="f_001")
    assert cert.status == "INCOMPLETE"
    assert cert.invariants["I9"].result == "missing"


def test_precedence_quarantined_outranks_incomplete():
    # If an evaluable invariant fails (e.g. matrix deviations) AND finding is incomplete,
    # QUARANTINED takes precedence per DEC-16.
    events = _build_clean_event_stream(finding="f_001")[:4]
    # Inject matrix deviation in pre-matrix
    events[2].body["deviations"] = 1
    _recompute_hashes(events)
    cert = evaluate_certificate(events, finding="f_001")
    assert cert.status == "QUARANTINED"
    assert cert.invariants["I2"].result == "fail"
