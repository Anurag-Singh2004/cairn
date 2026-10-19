"""FastAPI ASGI Switchboard application per context.md §8.2.

Implements:
- POST /v1/submit (Red tenant endpoint)
- POST /v1/probe/complete (Auditor probe endpoint)
- GET /v1/status (Tenant status endpoint)
- GET /v1/reveal/{role} (Commitment reveal endpoint)
- Admin configuration and lifecycle endpoints
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from cairn.common.clock import Clock, WallClock
from cairn.crypto.keys import public_key_from_b64
from cairn.crypto.tokens import verify_token
from cairn.model.sim_engine import SimEngine
from cairn.referee.controller import RunState
from cairn.switchboard.envelope import make_envelope
from cairn.switchboard.pipeline import SwitchboardPipeline
from cairn.switchboard.session import SessionManager
from cairn.switchboard.state import SwitchboardState
from cairn.tenants.blue.guard import BlueGuard


class SubmitRequest(BaseModel):
    session_id: str
    prompt: str
    finding_id: str = "f_000"


class ProbeRequest(BaseModel):
    session_id: str
    prompt: str


class ConfigureRunRequest(BaseModel):
    run_id: str
    pubkey_b64: str
    tier_config: dict[str, Any]
    secret_flag: str = ""
    secret_flag_hex: str = ""
    canaries: list[str] = []


class SetStateRequest(BaseModel):
    state: str


def create_switchboard_app(
    state: SwitchboardState | None = None,
    blue_guard: BlueGuard | None = None,
    model_engine: SimEngine | None = None,
    clock: Clock | None = None,
    event_sink: Any | None = None,
) -> FastAPI:
    """Factory to construct Switchboard FastAPI application."""
    sb_state = state or SwitchboardState()
    sb_blue = blue_guard or BlueGuard()
    sb_model = model_engine or SimEngine()
    sb_clock = clock or WallClock()
    sb_session = SessionManager(cache_isolation=sb_state.cache_isolation)

    pipeline = SwitchboardPipeline(
        state=sb_state,
        blue_guard=sb_blue,
        model_engine=sb_model,
        session_mgr=sb_session,
        clock=sb_clock,
        event_sink=event_sink,
    )

    app = FastAPI(title="CAIRN Switchboard", version="0.1.0")
    app.state.pipeline = pipeline
    app.state.sb_state = sb_state
    app.state.session_mgr = sb_session
    app.state.model = sb_model
    app.state.clock = sb_clock

    @app.post("/v1/submit")
    async def submit_attack(
        req: SubmitRequest,
        x_cairn_token: str | None = Header(default=None, alias="X-Cairn-Token"),
    ) -> dict[str, Any]:
        """Submit red attack payload through the defensive pipeline."""
        if not x_cairn_token:
            pipeline.emit_event(
                "violation.denied",
                {"reason": "Missing X-Cairn-Token header", "finding": req.finding_id},
            )
            raise HTTPException(status_code=401, detail="Missing X-Cairn-Token header")

        envelope, status = pipeline.process_request(
            token=x_cairn_token,
            session_id=req.session_id,
            prompt=req.prompt,
            finding_id=req.finding_id,
        )
        if status != 200:
            raise HTTPException(status_code=status, detail=envelope.get("error", "Request failed"))
        return envelope

    @app.post("/v1/probe/complete")
    async def probe_complete(
        req: ProbeRequest,
        x_cairn_token: str | None = Header(default=None, alias="X-Cairn-Token"),
    ) -> dict[str, Any]:
        """Direct probe endpoint for Auditor. Allowed only in PROBING state."""
        if not x_cairn_token:
            pipeline.emit_event("violation.denied", {"reason": "Missing probe token"})
            raise HTTPException(status_code=401, detail="Missing X-Cairn-Token header")

        if sb_state.state != RunState.PROBING:
            pipeline.emit_event(
                "violation.denied",
                {"reason": f"Probe disallowed in state {sb_state.state.value}"},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Probing disallowed in state {sb_state.state.value}",
            )

        try:
            claims = verify_token(
                x_cairn_token,
                sb_state.referee_pubkey,
                expected_run=sb_state.run_id,
                required_cap="probe.complete",
                expected_role="auditor",
                session_id=req.session_id,
                now_ns=sb_clock.now_ns(),
            )
            sb_session.record_call(x_cairn_token, claims.max_calls)
        except Exception as e:
            pipeline.emit_event("violation.denied", {"reason": str(e)})
            raise HTTPException(status_code=401, detail=f"Unauthorized: {e}") from e

        # Probe session gets its own isolated namespace
        probe_namespace = f"probe_{req.session_id}"
        comp = sb_model.complete(req.prompt, namespace=probe_namespace)

        envelope = make_envelope(comp["text"], sb_state.body_buckets)
        envelope["latency_ms"] = comp["timings"]["latency_ms"]
        return envelope

    @app.get("/v1/status")
    async def get_status(
        x_cairn_token: str | None = Header(default=None, alias="X-Cairn-Token"),
    ) -> dict[str, str]:
        """Tenant status endpoint per context.md §8.2."""
        if not x_cairn_token:
            raise HTTPException(status_code=401, detail="Missing X-Cairn-Token header")

        try:
            verify_token(
                x_cairn_token,
                sb_state.referee_pubkey,
                expected_run=sb_state.run_id,
                now_ns=sb_clock.now_ns(),
            )
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Unauthorized: {e}") from e

        if sb_state.state == RunState.RUNNING:
            return {"state": "running"}
        return {"state": "sealed"}

    @app.get("/v1/reveal/{role}")
    async def get_reveal(role: str) -> dict[str, Any]:
        """Per policy: 403 unless state in {CERTIFIED, RELEASED}."""
        if sb_state.state not in (RunState.CERTIFIED, RunState.RELEASED):
            pipeline.emit_event(
                "violation.denied",
                {"endpoint": f"/v1/reveal/{role}", "state": sb_state.state.value},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Reveal forbidden in state {sb_state.state.value}",
            )
        return {"role": role, "status": "revealed"}

    # Admin endpoints
    @app.post("/admin/run/configure")
    async def admin_configure(req: ConfigureRunRequest) -> dict[str, str]:
        pubkey = public_key_from_b64(req.pubkey_b64)
        sb_state.configure(
            run_id=req.run_id,
            referee_pubkey=pubkey,
            tier_config=req.tier_config,
            secret_flag=req.secret_flag,
            secret_flag_hex=req.secret_flag_hex,
            canaries=req.canaries,
        )
        sb_session.cache_isolation = sb_state.cache_isolation
        return {"status": "configured", "run_id": req.run_id}

    @app.post("/admin/run/state")
    async def admin_set_state(req: SetStateRequest) -> dict[str, str]:
        sb_state.set_state(req.state)
        return {"status": "state_updated", "state": sb_state.state.value}

    @app.get("/admin/health")
    async def admin_health() -> dict[str, str]:
        return {"status": "healthy", "state": sb_state.state.value}

    return app
