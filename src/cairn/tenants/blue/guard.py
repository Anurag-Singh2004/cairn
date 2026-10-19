"""Blue defense filter component for input and output filtering.

Implements context.md §8.3:
- Input filtering against injection patterns
- Output filtering against flag and canary leakage
- Fixed reason code enumeration
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

R_NONE = "R_NONE"
R_INPUT_PROMPT_INJECTION = "R_INPUT_PROMPT_INJECTION"
R_INPUT_INJECTION = "R_INPUT_INJECTION"
R_OUTPUT_FLAG_LEAK = "R_OUTPUT_FLAG_LEAK"
R_OUTPUT_CANARY_LEAK = "R_OUTPUT_CANARY_LEAK"


class BlueGuard:
    """Evaluates input and output text against defensive filter rules."""

    def __init__(
        self,
        policy_path: Path | str | None = None,
        policy: dict[str, Any] | None = None,
        canary_token: str = "",
        canary: str = "",
    ) -> None:
        self.input_filters: list[tuple[re.Pattern, str]] = []
        self.output_filters: list[tuple[re.Pattern, str]] = []
        self.canaries: list[str] = []

        if policy_path:
            self.load_policy_file(policy_path)
        elif policy:
            self.load_policy(policy, canary=canary_token or canary)

    def load_policy_file(self, path: Path | str) -> None:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.load_policy(data)

    def load_policy(self, data: dict[str, Any], canary: str = "") -> None:
        self.input_filters = [
            (re.compile(f["pattern"]), f.get("reason", R_INPUT_INJECTION))
            for f in data.get("input_filters", [])
        ]
        self.output_filters = [
            (re.compile(f["pattern"]), f.get("reason", R_OUTPUT_FLAG_LEAK))
            for f in data.get("output_filters", [])
        ]
        self.canaries = list(data.get("canaries", []))
        if canary:
            self.canaries.append(canary)

    def filter_input(self, text: str) -> dict[str, str]:
        """Evaluate prompt against input filters."""
        for pattern, reason in self.input_filters:
            if pattern.search(text):
                return {"verdict": "block", "reason": reason}
        return {"verdict": "allow", "reason": R_NONE}

    def filter_output(self, text: str) -> dict[str, str]:
        """Evaluate model completion against output filters and canary checks."""
        for canary in self.canaries:
            if canary in text:
                return {"verdict": "block", "reason": R_OUTPUT_CANARY_LEAK}

        for pattern, reason in self.output_filters:
            if pattern.search(text):
                return {"verdict": "block", "reason": reason}

        return {"verdict": "allow", "reason": R_NONE}
