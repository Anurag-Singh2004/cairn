"""Remote HTTP adapters for BlueGuard and SimEngine.

Allows SwitchboardPipeline to communicate over container networks transparently
with the exact same interface as in-process objects.
"""

from __future__ import annotations

from typing import Any

import httpx


class RemoteBlueGuard:
    """HTTP client adapter implementing BlueGuard interface."""

    def __init__(self, base_url: str = "http://blue:8100", timeout_s: float = 2.0) -> None:
        self.base_url = base_url
        self.timeout_s = timeout_s

    def filter_input(self, text: str) -> dict[str, str]:
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(f"{self.base_url}/filter/input", json={"text": text})
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {"verdict": "block", "reason": "R_BLUE_TIMEOUT"}

    def filter_output(self, text: str) -> dict[str, str]:
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(f"{self.base_url}/filter/output", json={"text": text})
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {"verdict": "block", "reason": "R_BLUE_TIMEOUT"}


class RemoteModelEngine:
    """HTTP client adapter implementing SimEngine interface."""

    def __init__(self, base_url: str = "http://model:8200", timeout_s: float = 3.0) -> None:
        self.base_url = base_url
        self.timeout_s = timeout_s

    def complete(
        self,
        prompt: str,
        namespace: str = "default",
        max_tokens: int = 128,
        seed: int | None = None,
    ) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(
                    f"{self.base_url}/complete",
                    json={
                        "prompt": prompt,
                        "namespace": namespace,
                        "max_tokens": max_tokens,
                        "seed": seed,
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {
            "text": "I can't help with that.",
            "finish_reason": "error",
            "simulated": True,
            "timings": {"latency_ms": 0, "hit_tokens": 0, "miss_tokens": 0},
        }
