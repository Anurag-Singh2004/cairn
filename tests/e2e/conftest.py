"""Pytest fixtures for e2e Docker container tests."""

from __future__ import annotations

import contextlib
import time

import pytest

from cairn.referee.docker_ctl import (
    check_compose_available,
    check_docker_available,
    compose_down,
    compose_exec,
    compose_up,
    is_tier_running,
)


@pytest.fixture(scope="session", autouse=True)
def ensure_t1_containers():
    """Ensure T1 containers are running for Docker e2e tests.

    - Detects Docker availability and fails with a clear diagnostic when unavailable.
    - Ensures T1 services are running, building if needed.
    - Tracks whether the fixture started the services.
    - Tears down only the services it started, not containers already running before the test.
    - Cleans up partially started containers if setup fails.
    """
    docker_ok, docker_msg = check_docker_available()
    if not docker_ok:
        pytest.fail(f"Docker is required for e2e tests but unavailable: {docker_msg}")

    compose_ok, compose_msg = check_compose_available()
    if not compose_ok:
        pytest.fail(f"Docker Compose is required for e2e tests but unavailable: {compose_msg}")

    already_running = is_tier_running("t1")
    started_by_fixture = False

    if not already_running:
        try:
            compose_up("t1", build=False, timeout_s=90.0)
            started_by_fixture = True

            # Wait for uvicorn services to finish initialization and bind to listening ports
            start_wait = time.time()
            ready = False
            while time.time() - start_wait < 15.0:
                if is_tier_running("t1"):
                    rc_red, out_red, _ = compose_exec(
                        "t1",
                        "red",
                        [
                            "python",
                            "-m",
                            "cairn.tenants.netprobe",
                            "--targets",
                            "switchboard:8000",
                        ],
                        timeout_s=3.0,
                    )
                    rc_sb, out_sb, _ = compose_exec(
                        "t1",
                        "switchboard",
                        [
                            "python",
                            "-m",
                            "cairn.tenants.netprobe",
                            "--targets",
                            "blue:8100",
                            "model:8200",
                        ],
                        timeout_s=3.0,
                    )
                    if (
                        rc_red == 0
                        and '"reachable": true' in out_red
                        and rc_sb == 0
                        and out_sb.count('"reachable": true') >= 2
                    ):
                        ready = True
                        break
                time.sleep(0.5)

            if not ready:
                pytest.fail("T1 containers started but services did not become ready within 15s")
        except Exception as e:
            with contextlib.suppress(Exception):
                compose_down("t1")
            pytest.fail(f"Failed to start T1 containers for e2e tests: {e}")

    try:
        yield
    finally:
        if started_by_fixture:
            with contextlib.suppress(Exception):
                compose_down("t1")
