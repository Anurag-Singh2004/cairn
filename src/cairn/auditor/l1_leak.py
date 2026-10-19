"""Backward-compatibility shim for L1 probe.

NOTE: Per context.md §9.3 and flow.md §5, L1 is the Prefix-Cache Timing and Token Recovery probe.
Use cairn.auditor.l1_cache_timing.L1CacheTimingProbe directly.
"""

from __future__ import annotations

from cairn.auditor.l1_cache_timing import L1CacheTimingProbe

L1LeakProbe = L1CacheTimingProbe
