"""Unit tests for run lifecycle state machine transitions."""

from __future__ import annotations

import pytest

from cairn.common.errors import StateTransitionError
from cairn.referee.controller import RunState, RunStateMachine


def test_happy_path_lifecycle() -> None:
    sm = RunStateMachine(RunState.DRAFT)
    assert sm.state == RunState.DRAFT

    sm.transition_to(RunState.COMMITTED, "manifest frozen")
    assert sm.state == RunState.COMMITTED

    sm.transition_to(RunState.PREFLIGHT, "preflight start")
    assert sm.state == RunState.PREFLIGHT

    sm.transition_to(RunState.RUNNING, "doctor passed")
    assert sm.state == RunState.RUNNING

    sm.transition_to(RunState.PROBING, "attacks finished")
    assert sm.state == RunState.PROBING

    sm.transition_to(RunState.CONCLUDED, "probes finished")
    assert sm.state == RunState.CONCLUDED

    sm.transition_to(RunState.CERTIFIED, "certificates issued")
    assert sm.state == RunState.CERTIFIED

    sm.transition_to(RunState.RELEASED, "artifacts released")
    assert sm.state == RunState.RELEASED
    assert sm.is_terminal() is True


def test_failure_branches() -> None:
    # Preflight rejection
    sm = RunStateMachine(RunState.DRAFT)
    sm.transition_to(RunState.COMMITTED)
    sm.transition_to(RunState.PREFLIGHT)
    sm.transition_to(RunState.REJECTED, "doctor check failed")
    assert sm.state == RunState.REJECTED
    assert sm.is_terminal() is True

    # Aborted during running
    sm = RunStateMachine(RunState.DRAFT)
    sm.transition_to(RunState.COMMITTED)
    sm.transition_to(RunState.PREFLIGHT)
    sm.transition_to(RunState.RUNNING)
    sm.transition_to(RunState.ABORTED, "timeout")
    sm.transition_to(RunState.INCOMPLETE)
    assert sm.state == RunState.INCOMPLETE
    assert sm.is_terminal() is True

    # Verification failed at conclusion
    sm = RunStateMachine(RunState.DRAFT)
    sm.transition_to(RunState.COMMITTED)
    sm.transition_to(RunState.PREFLIGHT)
    sm.transition_to(RunState.RUNNING)
    sm.transition_to(RunState.PROBING)
    sm.transition_to(RunState.CONCLUDED)
    sm.transition_to(RunState.VERIFICATION_FAILED, "tampered log")
    sm.transition_to(RunState.QUARANTINED)
    assert sm.state == RunState.QUARANTINED
    assert sm.is_terminal() is True


def test_illegal_transitions_raise() -> None:
    sm = RunStateMachine(RunState.DRAFT)

    # Cannot skip straight to Running
    with pytest.raises(StateTransitionError, match="Illegal state transition"):
        sm.transition_to(RunState.RUNNING)

    # Cannot skip to Certified
    with pytest.raises(StateTransitionError):
        sm.transition_to(RunState.CERTIFIED)
