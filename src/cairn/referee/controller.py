"""Run lifecycle state machine per context.md §7.4 and flow.md §3.2.

Enforces strict legal transitions:
Draft -> Committed -> Preflight -> Running -> Probing -> Concluded -> Certified -> Released
Failure exits:
- Preflight -> Rejected
- Running/Probing -> Aborted -> Incomplete
- Concluded -> VerificationFailed -> Quarantined
"""

from __future__ import annotations

from enum import StrEnum

from cairn.common.errors import StateTransitionError


class RunState(StrEnum):
    """Enumeration of run lifecycle states."""

    DRAFT = "Draft"
    COMMITTED = "Committed"
    PREFLIGHT = "Preflight"
    REJECTED = "Rejected"
    RUNNING = "Running"
    PROBING = "Probing"
    CONCLUDED = "Concluded"
    CERTIFIED = "Certified"
    RELEASED = "Released"
    ABORTED = "Aborted"
    INCOMPLETE = "Incomplete"
    VERIFICATION_FAILED = "VerificationFailed"
    QUARANTINED = "Quarantined"


LEGAL_TRANSITIONS: dict[RunState, set[RunState]] = {
    RunState.DRAFT: {RunState.COMMITTED},
    RunState.COMMITTED: {RunState.PREFLIGHT},
    RunState.PREFLIGHT: {RunState.RUNNING, RunState.REJECTED},
    RunState.RUNNING: {RunState.PROBING, RunState.ABORTED},
    RunState.PROBING: {RunState.CONCLUDED, RunState.ABORTED},
    RunState.CONCLUDED: {RunState.CERTIFIED, RunState.VERIFICATION_FAILED},
    RunState.CERTIFIED: {RunState.RELEASED},
    RunState.ABORTED: {RunState.INCOMPLETE},
    RunState.VERIFICATION_FAILED: {RunState.QUARANTINED},
    RunState.REJECTED: set(),
    RunState.RELEASED: set(),
    RunState.INCOMPLETE: set(),
    RunState.QUARANTINED: set(),
}


class RunStateMachine:
    """Manages the state transitions of a CAIRN run."""

    def __init__(self, initial_state: RunState = RunState.DRAFT) -> None:
        self._state = initial_state
        self._history: list[tuple[RunState, str]] = [(initial_state, "initialization")]

    @property
    def state(self) -> RunState:
        return self._state

    @property
    def history(self) -> list[tuple[RunState, str]]:
        return list(self._history)

    def can_transition_to(self, target: RunState | str) -> bool:
        target_state = RunState(target) if isinstance(target, str) else target
        return target_state in LEGAL_TRANSITIONS.get(self._state, set())

    def transition_to(self, target: RunState | str, reason: str = "") -> None:
        target_state = RunState(target) if isinstance(target, str) else target
        allowed = LEGAL_TRANSITIONS.get(self._state, set())
        if target_state not in allowed:
            raise StateTransitionError(
                f"Illegal state transition from {self._state.value} to {target_state.value}"
                + (f" (reason: {reason})" if reason else "")
            )
        self._state = target_state
        self._history.append((target_state, reason))

    def is_terminal(self) -> bool:
        return len(LEGAL_TRANSITIONS.get(self._state, set())) == 0
