"""SimEngine: Deterministic simulated model with token-level prefix caching.

Implements context.md §5 (DEC-5), §8.3, and flow.md §5:
- Deterministic token-level prefix trie per namespace
- Latency model: base_ms + miss_tokens * c_miss_ms + hit_tokens * c_hit_ms + seeded_jitter
- Cross-session prefix cache timing leakage in 'shared' namespace (T0)
- Isolated prefix cache in 'salted' namespace (T1)
- Always marks output as simulated: True per REQ-G6
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any


class PrefixTrieNode:
    """Node in token-level prefix trie."""

    def __init__(self) -> None:
        self.children: dict[str, PrefixTrieNode] = {}


class SimEngine:
    """Deterministic model engine with calibrated prefix caching."""

    def __init__(
        self,
        rules_path: Path | str | None = None,
        *,
        base_ms: int = 20,
        c_miss_ms: int = 5,
        c_hit_ms: int = 1,
        seed: int = 1337,
    ) -> None:
        self.base_ms = base_ms
        self.c_miss_ms = c_miss_ms
        self.c_hit_ms = c_hit_ms
        self.seed = seed
        self._rng = random.Random(seed)

        # Namespaced prefix tries: namespace_id -> root PrefixTrieNode
        self._caches: dict[str, PrefixTrieNode] = {}

        self.rules: list[dict[str, Any]] = []
        self.secret_flag: str = "FLAG{cairn_isolated_s3cr3t_77}"
        self.secret_flag_hex: str = "464c41477b636169726e5f69736f6c617465645f7333637233745f37377d"
        self.default_completion: str = "I am a simulated model adhering to system instructions."

        if rules_path:
            self.load_rules_file(rules_path)

    def load_rules_file(self, path: Path | str) -> None:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.load_rules(data)

    def load_rules(self, data: dict[str, Any]) -> None:
        self.rules = data.get("rules", [])
        self.secret_flag = data.get("secret_flag", self.secret_flag)
        self.secret_flag_hex = data.get("secret_flag_hex", self.secret_flag_hex)
        self.default_completion = data.get("default_completion", self.default_completion)

    def reset_caches(self) -> None:
        """Clear all cached prefix tries."""
        self._caches.clear()

    def _tokenize(self, text: str) -> list[str]:
        """Simple deterministic whitespace and punctuation tokenizer."""
        # Using word-based tokenization suitable for prompt prefixes
        tokens = text.strip().split()
        return tokens if tokens else [""]

    def _lookup_and_insert_prefix(
        self,
        namespace: str,
        tokens: list[str],
    ) -> tuple[int, int]:
        """Lookup prefix in namespace cache and update trie.

        Returns (hit_tokens, miss_tokens).
        """
        if namespace not in self._caches:
            self._caches[namespace] = PrefixTrieNode()

        root = self._caches[namespace]
        curr = root
        hit_tokens = 0
        still_hitting = True

        for token in tokens:
            if still_hitting and token in curr.children:
                hit_tokens += 1
                curr = curr.children[token]
            else:
                still_hitting = False
                if token not in curr.children:
                    curr.children[token] = PrefixTrieNode()
                curr = curr.children[token]

        miss_tokens = len(tokens) - hit_tokens
        return hit_tokens, miss_tokens

    def complete(
        self,
        prompt: str,
        namespace: str = "default",
        max_tokens: int = 128,
        seed: int | None = None,
    ) -> dict[str, Any]:
        """Generate deterministic completion with calibrated latency.

        Always returns simulated: True per REQ-G6.
        """
        rng = random.Random(seed if seed is not None else self._rng.randint(0, 1_000_000))

        tokens = self._tokenize(prompt)
        hit_tokens, miss_tokens = self._lookup_and_insert_prefix(namespace, tokens)

        jitter = rng.randint(0, 2)
        latency_ms = (
            self.base_ms + (miss_tokens * self.c_miss_ms) + (hit_tokens * self.c_hit_ms) + jitter
        )

        matched_text = self.default_completion
        finish_reason = "stop"

        prompt_lower = prompt.lower()
        for rule in self.rules:
            if rule.get("trigger", "").lower() in prompt_lower:
                matched_text = rule.get("response", self.default_completion)
                break

        return {
            "text": matched_text,
            "finish_reason": finish_reason,
            "simulated": True,
            "timings": {
                "latency_ms": latency_ms,
                "hit_tokens": hit_tokens,
                "miss_tokens": miss_tokens,
            },
        }
