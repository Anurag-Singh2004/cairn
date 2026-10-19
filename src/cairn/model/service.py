"""HTTP service for Model (SimEngine) running inside the model container."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from cairn.model.sim_engine import SimEngine

app = FastAPI(title="CAIRN Model Service", version="0.1.0")
engine = SimEngine()


class CompleteRequest(BaseModel):
    prompt: str
    namespace: str = "default"
    max_tokens: int = 128
    seed: int | None = None


class LoadModelRequest(BaseModel):
    rules: list[dict[str, Any]] = []
    secret_flag: str = ""
    secret_flag_hex: str = ""
    default_completion: str = ""


@app.post("/complete")
async def complete(req: CompleteRequest) -> dict[str, Any]:
    return engine.complete(
        prompt=req.prompt,
        namespace=req.namespace,
        max_tokens=req.max_tokens,
        seed=req.seed,
    )


@app.post("/control/load")
async def control_load(req: LoadModelRequest) -> dict[str, str]:
    engine.load_rules(
        {
            "rules": req.rules,
            "secret_flag": req.secret_flag,
            "secret_flag_hex": req.secret_flag_hex,
            "default_completion": req.default_completion,
        }
    )
    return {"status": "rules_loaded"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "model"}
