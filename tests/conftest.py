"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip Docker-dependent tests unless explicitly requested."""
    if config.getoption("-m", default=None) != "docker":
        skip_docker = pytest.mark.skip(
            reason="requires Docker container environment (run with make test-e2e or -m docker)"
        )
        for item in items:
            if "docker" in item.keywords:
                item.add_marker(skip_docker)
