"""Host-side Docker and Docker Compose controller for CAIRN tiers.

Follows build_prompt.md §7:
- Subprocess with argument lists (no shell interpolation)
- Explicit timeouts and stderr capture
- Custom error handling with PreflightError / CairnError
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from cairn.common.errors import PreflightError

REPO_ROOT = Path(__file__).resolve().parents[3]


def get_compose_file(tier: str) -> Path:
    path = REPO_ROOT / "compose" / f"compose.{tier}.yml"
    if not path.is_file():
        raise PreflightError(f"Compose file not found for tier '{tier}': {path}")
    return path


def check_docker_available() -> tuple[bool, str]:
    """Check if docker daemon is running and reachable."""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0:
            return True, "Docker daemon reachable"
        return False, proc.stderr.strip() or "Docker daemon returned non-zero"
    except Exception as e:
        return False, str(e)


def check_compose_available() -> tuple[bool, str]:
    """Check if docker compose is available."""
    try:
        proc = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0:
            return True, proc.stdout.strip()
        return False, proc.stderr.strip() or "docker compose command failed"
    except Exception as e:
        return False, str(e)


def compose_up(tier: str, build: bool = False, timeout_s: float = 60.0) -> None:
    """Start services for the specified tier."""
    compose_file = get_compose_file(tier)
    cmd = ["docker", "compose", "-p", f"cairn-{tier}", "-f", str(compose_file), "up", "-d"]
    if build:
        cmd.append("--build")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    if proc.returncode != 0:
        raise PreflightError(f"docker compose up failed for tier {tier}: {proc.stderr}")


def compose_down(tier: str, timeout_s: float = 30.0) -> None:
    """Tear down services for the specified tier."""
    compose_file = get_compose_file(tier)
    cmd = [
        "docker",
        "compose",
        "-p",
        f"cairn-{tier}",
        "-f",
        str(compose_file),
        "down",
        "--remove-orphans",
    ]
    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )


def compose_exec(
    tier: str,
    service: str,
    cmd: list[str],
    input_str: str | None = None,
    timeout_s: float = 30.0,
) -> tuple[int, str, str]:
    """Execute command inside a running service container."""
    compose_file = get_compose_file(tier)
    full_cmd = [
        "docker",
        "compose",
        "-p",
        f"cairn-{tier}",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        service,
        *cmd,
    ]
    proc = subprocess.run(
        full_cmd,
        input=input_str,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def inspect_service_container(tier: str, service: str) -> dict[str, Any]:
    """Inspect low-level container config via docker inspect."""
    compose_file = get_compose_file(tier)
    cmd = [
        "docker",
        "compose",
        "-p",
        f"cairn-{tier}",
        "-f",
        str(compose_file),
        "ps",
        "-q",
        service,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0, check=False)
    cid = proc.stdout.strip()
    if not cid:
        raise PreflightError(f"Container for service '{service}' not found")

    inspect_cmd = ["docker", "inspect", cid]
    ins_proc = subprocess.run(
        inspect_cmd,
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )
    data = json.loads(ins_proc.stdout)
    return data[0] if data else {}


def get_compose_sha256(tier: str) -> str:
    """Compute SHA-256 hash of the tier's docker-compose configuration file."""
    from cairn.common.hashing import sha256_hex

    compose_file = get_compose_file(tier)
    return sha256_hex(compose_file.read_bytes())


def get_container_image_ids(tier: str, services: list[str] | None = None) -> dict[str, str]:
    """Inspect and return actual image digests for running services."""
    svcs = services or ["switchboard", "blue", "model", "red"]
    image_ids: dict[str, str] = {}
    for svc in svcs:
        try:
            info = inspect_service_container(tier, svc)
            img_id = info.get("Image")
            if not img_id:
                raise PreflightError(f"Missing Image in inspect for {svc}")
            image_ids[svc] = str(img_id)
        except Exception as e:
            raise PreflightError(f"Failed to inspect image for service '{svc}': {e}") from e
    return image_ids


def is_tier_running(tier: str, services: list[str] | None = None) -> bool:
    """Check if all services in the tier are running."""
    svcs = services or ["switchboard", "blue", "model", "red"]
    for svc in svcs:
        try:
            info = inspect_service_container(tier, svc)
            if not info.get("State", {}).get("Running", False):
                return False
        except Exception:
            return False
    return True
