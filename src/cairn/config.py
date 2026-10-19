"""Configuration loader for CAIRN tiers and pre-registered thresholds per context.md §11."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_thresholds(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load pre-registered thresholds from configs/thresholds.toml."""
    path = Path(config_path) if config_path else REPO_ROOT / "configs" / "thresholds.toml"
    if not path.is_file():
        # Fallback to defaults matching thresholds.toml
        return {
            "l1": {
                "n_trials_per_class": 200,
                "leak_auc_lower_ci": 0.65,
                "chance_recovery_multiple": 5,
                "bootstrap_resamples": 1000,
                "seed": 1337,
            },
            "l3": {
                "leak_auc_lower_ci": 0.65,
            },
            "positive_control": {
                "required": ["l1", "l4"],
            },
        }
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_tier_config(tier: str, config_path: Path | str | None = None) -> dict[str, Any]:
    """Load tier configuration (configs/t0.toml or configs/t1.toml)."""
    tier_name = tier.lower()
    path = Path(config_path) if config_path else REPO_ROOT / "configs" / f"{tier_name}.toml"
    if not path.is_file():
        raise FileNotFoundError(f"Tier configuration not found: {path}")
    with open(path, "rb") as f:
        return tomllib.load(f)
