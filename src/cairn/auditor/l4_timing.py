"""Backward-compatibility shim for L4 probe.

NOTE: Per context.md §9.3 and flow.md §5, L4 is the Filesystem/Shared-Volume and Environment
enumeration probe (cairn.auditor.l4_fs.L4FsProbe), while L1 is the Prefix-Cache Timing probe
(cairn.auditor.l1_cache_timing.L1CacheTimingProbe).
"""

from __future__ import annotations

from cairn.auditor.l4_fs import L4FsProbe

# Retain alias for legacy references
L4TimingProbe = L4FsProbe
