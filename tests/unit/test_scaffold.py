"""Scaffold tests — verify the M0 project structure is valid."""

from __future__ import annotations

import importlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cairn_package_importable() -> None:
    """The cairn package must be importable after 'pip install -e .'."""
    mod = importlib.import_module("cairn")
    assert mod is not None


def test_required_configs_exist() -> None:
    """Pre-registered thresholds and tier configs must exist (DEC-17)."""
    for name in ("configs/t0.toml", "configs/t1.toml", "configs/thresholds.toml"):
        path = REPO_ROOT / name
        assert path.is_file(), f"Missing required config: {name}"


def test_thresholds_parseable() -> None:
    """thresholds.toml must parse and contain the pre-registered sections."""
    import tomllib

    path = REPO_ROOT / "configs" / "thresholds.toml"
    with open(path, "rb") as f:
        data = tomllib.load(f)
    assert "l1" in data, "thresholds.toml missing [l1] section"
    assert "positive_control" in data, "thresholds.toml missing [positive_control] section"
    assert data["l1"]["seed"] == 1337, "seed must be pre-registered"


def test_directory_structure() -> None:
    """Key directories from context.md §11 must exist."""
    required_dirs = [
        "src/cairn/common",
        "src/cairn/crypto",
        "src/cairn/referee",
        "src/cairn/switchboard",
        "src/cairn/tenants/red",
        "src/cairn/tenants/blue",
        "src/cairn/model",
        "src/cairn/auditor",
        "configs",
        "compose",
        "data/attack_packs",
        "data/policies",
        "docs",
        "tests/unit",
        "tests/integration",
        "tests/e2e",
        "tests/fixtures",
    ]
    for d in required_dirs:
        assert (REPO_ROOT / d).is_dir(), f"Missing directory: {d}"
