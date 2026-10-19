"""Custom error hierarchy for CAIRN.

Follows context.md §13 conventions:
- CairnError base class
- Fail-closed security semantics
- Clear exit codes:
  0: ok
  1: verification / invariant failure
  2: usage / configuration error
  3: environment / preflight failure
"""

from __future__ import annotations


class CairnError(Exception):
    """Base exception for all CAIRN errors."""

    exit_code: int = 1


class UsageError(CairnError):
    """Command line usage or argument error."""

    exit_code: int = 2


class ConfigError(CairnError):
    """Configuration parsing or schema error."""

    exit_code: int = 2


class PreflightError(CairnError):
    """Environment or preflight check failure (cairn doctor)."""

    exit_code: int = 3


class VerificationError(CairnError):
    """Audit evidence, Merkle proof, signature or invariant check failure."""

    exit_code: int = 1

    def __init__(self, message: str, step: str = "") -> None:
        super().__init__(message)
        self.step = step


class CanonicalizationError(CairnError):
    """Error canonicalizing data (e.g. floats encountered per DEC-19)."""

    exit_code: int = 1


class CryptoError(CairnError):
    """Cryptographic operation or key management failure."""

    exit_code: int = 1


class TokenError(CairnError):
    """Capability token validation failure."""

    exit_code: int = 1


class StateTransitionError(CairnError):
    """Illegal run state machine transition."""

    exit_code: int = 1


class EvidenceError(CairnError):
    """Evidence store or hash chain integrity failure."""

    exit_code: int = 1
