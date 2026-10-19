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

---

## 19 Oct 2026 17:45 IST — M1: Evidence core

**Done:**
- Created `cairn.common.canonical`: canonical JSON with float rejection per DEC-19
- Created `cairn.common.hashing`: SHA-256 and RFC 6962 domain-separated hashing
- Created `cairn.common.clock`: Clock protocol, WallClock, FakeClock
- Created `cairn.common.ids`: run, session, and finding identifier generators
- Created `cairn.common.schemas`: Pydantic wire models (Event, Checkpoint, TokenClaims, Receipt, Certificate)
- Created `cairn.common.errors`: CairnError hierarchy with standard exit codes (0, 1, 2, 3)
- Created `cairn.crypto.keys`: Ed25519 key generation, PEM serialization, 0600 file permission enforcement, sign/verify
- Created `cairn.crypto.merkle`: RFC 6962 Merkle tree, MTH root, inclusion proofs, verification
- Created `cairn.crypto.commit`: commit-reveal primitives for red attack packs and blue policies
- Created `cairn.crypto.tokens`: Ed25519-signed capability tokens (minting, verification, expiry, cap checking)
- Created `cairn.referee.controller`: Run lifecycle state machine with strictly enforced legal transitions
- Created `cairn.referee.evidence`: SQLite append-only evidence store in WAL mode, hash-chaining, signed checkpoints
- Created `cairn.referee.verify`: 5-step receipt verifier that identifies the first failing step
- Created `cairn.cli`: `cairn keygen` and `cairn verify` commands

**Verified by:**
- `make lint` → exit 0 (Ruff check clean, 34 files properly formatted)
- `make test` → exit 0 (21 passed in 0.26s)
- Canonical JSON stability, sorted keys, float rejection tested
- RFC 6962 empty tree root = SHA-256(""), single leaf root = SHA-256(0x00 || leaf) tested
- Merkle inclusion proofs exhaustively tested for all tree sizes 1..65 and every leaf index 0..n-1
- Merkle negative controls: leaf bit flip, proof bit flip, root bit flip all fail verification
- Ed25519 sign/verify roundtrip, corrupted signature detection, wrong key rejection tested
- Private key file permissions verified as 0600
- Capability tokens verified: valid tokens accept, expired tokens reject, missing caps reject, tampered tokens reject
- Commit-reveal verified for red and blue, tampered payload rejects
- State machine verified: legal path Draft->Committed->Preflight->Running->Probing->Concluded->Certified->Released; failure exits; illegal transitions raise StateTransitionError
- Negative control test: editing one stored event in a 50-event receipt fails Step 2; corrupting checkpoint signature fails Step 1; tampering inclusion proof fails Step 3
- CLI keygen executed: generated keypair in test dir with 0600 private key permissions

**Decisions:** (none new; followed DEC-4, DEC-6, DEC-16, DEC-18, DEC-19)

**Known gaps:**
- Invariants engine (I1-I9) full evaluation logic is stubbed for M5; basic certificate check in place
- Pipeline in-process (SimEngine, blue, red, switchboard) is next

**Next:** M2 — In-process pipeline (SimEngine, Blue guard, Red agent, Switchboard logic, envelope, release timing, fixtures)

---

## 19 Oct 2026 17:51 IST — M2: In-process pipeline

**Done:**
- Created `cairn.model.sim_engine`: deterministic SimEngine with token-level prefix caching, latency calibration, and SIMULATED marker per REQ-G6
- Created `cairn.tenants.blue.guard`: BlueGuard with regex input/output filters, canary leak detection, and standardized reason codes
- Created `cairn.tenants.red.agent`: RedAgent runner supporting in-process and async HTTP submission
- Created `cairn.switchboard.envelope`: Uniform response envelope with space padding to configurable buckets per DEC-13
- Created `cairn.switchboard.release`: Quantized release timing (Δ * ceil(proc_ms / Δ)) and deadline timeout enforcement
- Created `cairn.switchboard.session`: Session and token budget tracking, cache namespace derivation (shared vs salted)
- Created `cairn.switchboard.state`: Switchboard configuration and run state management
- Created `cairn.switchboard.pipeline`: Full request processing pipeline with fail-closed semantics, ground-truth judge (plain + hex secret flag), and event emission
- Created `cairn.switchboard.app`: FastAPI ASGI application with `/v1/submit`, `/v1/probe/complete`, `/v1/status`, `/v1/reveal/{role}`, and admin endpoints
- Created data fixtures: `data/sim_rules.json`, `data/policies/demo_blue.json`, `data/attack_packs/demo.json` (~12 synthetic attacks)

**Verified by:**
- `make lint` → exit 0 (Ruff check clean, 44 files properly formatted)
- `make test` → exit 0 (27 passed in 0.45s)
- Request-path tested: reproduces allow, input-block, output-block, model-refusal, and evasive bypass
- Uniformity test: envelopes for input-block, model-refusal, and output-block are byte-identical in shape (body padded to 128 chars, bucket=128)
- Release test: verified quantized release timing multiple of Δ (120ms delay released at 250ms), over-deadline releases refusal + `infra.timeout`
- AuthZ negative controls: no token -> 401, expired token -> 401, wrong run -> 401, calls outside RUNNING -> 403, reveal before Certified -> 403
- SimEngine prefix cache timing verified: shared namespace exhibits cache hits and lower latency on identical prefixes; salted namespace yields zero cross-session cache hits
- Full red attack pack (12 attacks) executed against Switchboard pipeline in-process; generated events validated cryptographic hash chain on SQLite EvidenceStore

**Decisions:** (none new; followed DEC-5, DEC-8, DEC-10, DEC-13, DEC-15)

**Known gaps:**
- Containerization and Docker Compose setup (T0/T1) is next (M3)

**Next:** M3 — Containers, tiers, doctor (compose/Dockerfile, compose.t0.yml, compose.t1.yml, UDS admin, netprobe, matrix, cairn doctor)
