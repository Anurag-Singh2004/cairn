"""Session and token budget tracking for Switchboard."""

from __future__ import annotations

from cairn.common.errors import TokenError


class SessionManager:
    """Manages session namespaces and capability token call budgets."""

    def __init__(self, cache_isolation: str = "salted") -> None:
        self.cache_isolation = cache_isolation
        self._token_calls: dict[str, int] = {}

    def get_cache_namespace(self, session_id: str) -> str:
        """Derive prefix cache namespace based on tier cache_isolation policy."""
        if self.cache_isolation == "shared":
            return "shared"
        elif self.cache_isolation == "salted":
            return f"sess_salt_{session_id}"
        else:
            return "default"

    def record_call(self, token: str, max_calls: int) -> int:
        """Increment call counter for token; raises TokenError if budget exceeded."""
        current = self._token_calls.get(token, 0)
        if current >= max_calls:
            raise TokenError(f"Token query budget exceeded ({current} >= {max_calls})")
        self._token_calls[token] = current + 1
        return current + 1

    def get_calls(self, token: str) -> int:
        return self._token_calls.get(token, 0)
