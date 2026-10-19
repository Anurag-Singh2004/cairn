# CAIRN — Progress Log

---

## 19 Oct 2026 17:25 IST — M0: Orientation and scaffold

**Done:**
- Read `context.md`, `flow.md`, `build_prompt.md` in full
- Inspected repo (empty, no commits — ASM-1 confirmed), `git status`, environment
- Wrote `ENVIRONMENT.md`: native Arch Linux, kernel 7.2.7, 12 CPUs, 16 GB RAM, cgroup v2, Python 3.14.7, Docker 29.8.1, Compose v5.5.1, no WSL, no Docker Desktop — results are **not** `dev-only`
- Created full directory structure per `context.md` §11
- Created `pyproject.toml`, `Makefile`, `.gitignore`, `.env.example`, `requirements.lock`
- Created `configs/t0.toml`, `configs/t1.toml`, `configs/thresholds.toml` (pre-registered per DEC-17, committed before any measurement)
- Created `.github/workflows/ci.yml`
- Created `README.md` skeleton, `DECISIONS.md`, this file
- Created 4 scaffold tests in `tests/unit/test_scaffold.py`
- Installed dependencies in `.venv`

**Verified by:**
- `make lint` → exit 0 ("All checks passed!", "15 files already formatted")
- `make test` → exit 0 (4 passed in 0.01s: `test_cairn_package_importable`, `test_required_configs_exist`, `test_thresholds_parseable`, `test_directory_structure`)
- `git status` → only expected files tracked; `.venv`, `keys/`, `runs/`, caches all ignored
- `docker version` → Docker Engine 29.8.1, native Linux
- `docker compose version` → Compose v5.5.1

**Decisions:** DEC-20 (OQ-1 default), DEC-21 (OQ-4 no licence), DEC-22 (Python 3.14 compat)

**Known gaps:**
- OQ-1 (Unstop requirements) unresolved — using defaults
- OQ-4 (licence) unresolved — no licence added
- No functional code yet — all P0 items from §6.1 pending

**Gate G1 (Environment):** ✅ GREEN — Docker + Compose work, Python ≥ 3.11

**Next:** M1 — Evidence core (canonical JSON, hashing, Ed25519 keys, Merkle tree, commit-reveal, state machine, verify)
