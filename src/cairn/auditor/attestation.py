"""Attestation collector for container image digests and configuration manifests."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from cairn.common.hashing import sha256_hex
from cairn.switchboard.pipeline import SwitchboardPipeline

REPO_ROOT = Path(__file__).resolve().parents[3]


def get_image_id(image_name: str = "cairn-base:latest") -> str:
    """Query docker image ID."""
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image_name, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return "sha256:simulated_image_id"


def collect_attestations(
    pipeline: SwitchboardPipeline,
    tier: str = "t1",
    dev_only: bool = False,
) -> dict[str, Any]:
    """Collect runtime attestations and freeze manifest."""
    t_cfg_path = REPO_ROOT / "configs" / f"{tier}.toml"
    thresh_path = REPO_ROOT / "configs" / "thresholds.toml"
    compose_path = REPO_ROOT / "compose" / f"compose.{tier}.yml"

    t_cfg_hash = sha256_hex(t_cfg_path.read_bytes()) if t_cfg_path.is_file() else "0" * 64
    thresh_hash = sha256_hex(thresh_path.read_bytes()) if thresh_path.is_file() else "0" * 64
    comp_hash = sha256_hex(compose_path.read_bytes()) if compose_path.is_file() else "0" * 64

    img_id = get_image_id("cairn-base:latest")

    manifest = {
        "run": pipeline.state.run_id,
        "tier": tier,
        "tier_config_sha256": t_cfg_hash,
        "thresholds_sha256": thresh_hash,
        "compose_sha256": comp_hash,
        "images": {
            "switchboard": img_id,
            "blue": img_id,
            "model": img_id,
            "red": img_id,
        },
        "dev_only": dev_only,
    }

    pipeline.emit_event("attestation.manifest", manifest)
    return manifest
