"""Red team attack agent per context.md §8.1 and flow.md §5 M2.

Submits synthetic attack pack prompts to the Switchboard /v1/submit endpoint
using an Ed25519-signed capability token.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from cairn.switchboard.pipeline import SwitchboardPipeline


class RedAgent:
    """Attacker agent executing attack packs against Switchboard."""

    def __init__(
        self,
        token: str,
        session_id: str,
        pack_data: dict[str, Any] | None = None,
        pack_path: Path | str | None = None,
    ) -> None:
        self.token = token
        self.session_id = session_id
        self.attacks: list[dict[str, Any]] = []

        if pack_path:
            with open(pack_path, encoding="utf-8") as f:
                data = json.load(f)
            self.attacks = data.get("attacks", [])
        elif pack_data:
            self.attacks = pack_data.get("attacks", [])

    def run_in_process(
        self,
        pipeline: SwitchboardPipeline,
    ) -> list[dict[str, Any]]:
        """Run pack directly through in-process Switchboard pipeline."""
        results: list[dict[str, Any]] = []
        for atk in self.attacks:
            finding_id = atk.get("id", "f_000")
            prompt = atk.get("prompt", "")
            envelope, status = pipeline.process_request(
                token=self.token,
                session_id=self.session_id,
                prompt=prompt,
                finding_id=finding_id,
            )
            results.append(
                {
                    "finding_id": finding_id,
                    "prompt": prompt,
                    "status_code": status,
                    "envelope": envelope,
                }
            )
        return results

    async def run_async_http(
        self,
        base_url: str,
        client: httpx.AsyncClient | None = None,
    ) -> list[dict[str, Any]]:
        """Run pack via HTTP / ASGI client."""
        results: list[dict[str, Any]] = []
        headers = {"X-Cairn-Token": self.token}

        async def _run(c: httpx.AsyncClient) -> None:
            for atk in self.attacks:
                finding_id = atk.get("id", "f_000")
                payload = {
                    "session_id": self.session_id,
                    "prompt": atk.get("prompt", ""),
                    "finding_id": finding_id,
                }
                resp = await c.post(
                    f"{base_url}/v1/submit",
                    json=payload,
                    headers=headers,
                )
                results.append(
                    {
                        "finding_id": finding_id,
                        "status_code": resp.status_code,
                        "data": resp.json() if resp.status_code == 200 else resp.text,
                    }
                )

        if client is not None:
            await _run(client)
        else:
            async with httpx.AsyncClient() as new_client:
                await _run(new_client)

        return results
