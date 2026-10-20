"""Attestation collector for container image digests and configuration manifests."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from cairn.common.hashing import sha256_hex
from cairn.switchboard.pipeline import SwitchboardPipeline

REPO_ROOT = Path(__file__).resolve().parents[3]


def get_image_id(image_name: str = "cairn-base:latest") -> str:
    """Query docker image ID; fails closed if inspect fails."""
    from cairn.common.errors import PreflightError

    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image_name, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        err_msg = proc.stderr.strip()
        raise PreflightError(f"docker image inspect failed for {image_name}: {err_msg}")
    except Exception as e:
        raise PreflightError(f"Failed to inspect runtime image {image_name}: {e}") from e


def collect_attestations(
    pipeline: SwitchboardPipeline,
    tier: str = "t1",
    dev_only: bool = False,
) -> dict[str, Any]:
    """Collect runtime attestations and freeze manifest."""
    from cairn.referee.docker_ctl import (
        get_compose_sha256,
        get_container_image_ids,
        is_tier_running,
    )

    t_cfg_path = REPO_ROOT / "configs" / f"{tier}.toml"
    thresh_path = REPO_ROOT / "configs" / "thresholds.toml"

    t_cfg_hash = sha256_hex(t_cfg_path.read_bytes()) if t_cfg_path.is_file() else "0" * 64
    thresh_hash = sha256_hex(thresh_path.read_bytes()) if thresh_path.is_file() else "0" * 64
    comp_hash = get_compose_sha256(tier)

    if is_tier_running(tier):
        images = get_container_image_ids(tier)
    else:
        img_id = get_image_id("cairn-base:latest")
        images = {
            "switchboard": img_id,
            "blue": img_id,
            "model": img_id,
            "red": img_id,
        }

    manifest = {
        "run": pipeline.state.run_id,
        "tier": tier,
        "tier_config_sha256": t_cfg_hash,
        "thresholds_sha256": thresh_hash,
        "compose_sha256": comp_hash,
        "images": images,
        "dev_only": dev_only,
    }

    pipeline.emit_event("attestation.manifest", manifest)
    return manifest
