# CAIRN — Environment Report

> Generated: 19 Oct 2026, 17:16 IST (M0 orientation)

## Host

| Property | Value |
|---|---|
| OS | Arch Linux, kernel 7.2.7-arch1-1, x86_64 |
| WSL2 | **No** — native Linux |
| CPU | 12 cores |
| RAM | 16 GB (≈9.2 GB available) |
| cgroup | **v2** (unified, `cgroup2`) |
| `dev-only` | **No** — native Linux Docker Engine; results are NOT `dev-only` |

## Python

| Property | Value |
|---|---|
| Version | 3.14.7 (exceeds ≥3.11 requirement ✓) |
| `tomllib` | available (stdlib) |
| `sqlite3` | available (stdlib) |
| `hashlib` | available (stdlib) |

## Docker

| Property | Value |
|---|---|
| Docker Engine | 29.8.1 (API 1.56, native Linux, not Docker Desktop) |
| containerd | 2.4.1 |
| runc | 1.5.2 |
| Docker Compose | v5.5.1 (Compose v2 ✓) |

## Optional / P2 tools

| Tool | Status |
|---|---|
| `runsc` (gVisor) | **Not found** — T2 tier not available (P2 anyway, DEC-14) |
| `llama-server` (llama.cpp) | **Not found** — real-engine backend not available; SimEngine is primary (DEC-5) |

## Assumptions verified

| ASM | Result |
|---|---|
| ASM-1 | **Confirmed**: repo has no commits; only the 4 planning docs exist |
| ASM-2 | **Confirmed**: Docker Engine + Compose v2 on native Linux |
| ASM-5 | **Confirmed**: Python 3.14.7 ≥ 3.11 |
| ASM-9 | **Not applicable**: this is native Linux, not Docker Desktop |
