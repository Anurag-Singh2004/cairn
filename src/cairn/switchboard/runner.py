"""Dual-listener runner for Switchboard: TCP 8000 tenant API + UDS admin.sock.

Runs both:
- TCP 0.0.0.0:8000 for tenant requests (from red)
- Unix domain socket /run/cairn/admin.sock for referee control plane (DEC-3)
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn

from cairn.switchboard.app import create_switchboard_app
from cairn.switchboard.remote_adapters import RemoteBlueGuard, RemoteModelEngine
from cairn.switchboard.state import SwitchboardState


async def run_servers() -> None:
    state = SwitchboardState()
    blue = RemoteBlueGuard(base_url="http://blue:8100")
    model = RemoteModelEngine(base_url="http://model:8200")

    app = create_switchboard_app(
        state=state,
        blue_guard=blue,
        model_engine=model,
    )

    uds_path = Path("/run/cairn/admin.sock")
    uds_path.parent.mkdir(parents=True, exist_ok=True)
    if uds_path.exists():
        uds_path.unlink()

    bind_host = os.environ.get("CAIRN_BIND_HOST", "172.28.1.10")

    # Config for internal TCP server (tenant API)
    tcp_config = uvicorn.Config(
        app,
        host=bind_host,
        port=8000,
        log_level="info",
        access_log=False,
    )
    tcp_server = uvicorn.Server(tcp_config)

    # Config for Unix domain socket (admin API)
    uds_config = uvicorn.Config(
        app,
        uds=str(uds_path),
        log_level="info",
        access_log=False,
    )
    uds_server = uvicorn.Server(uds_config)

    await asyncio.gather(tcp_server.serve(), uds_server.serve())


def main() -> None:
    asyncio.run(run_servers())


if __name__ == "__main__":
    main()
