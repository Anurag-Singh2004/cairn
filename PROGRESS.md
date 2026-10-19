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

---

## 19 Oct 2026 18:03 IST — M3: Containers, tiers, and doctor

**Done:**
- Created `compose/Dockerfile`: base image `python:3.12-slim` with non-root user `cairn` (UID 10001)
- Created `compose/compose.t1.yml`: Hardened OCI tier (internal networks `red-net`, `blue-net`, `model-net`; read-only rootfs; `cap_drop: ["ALL"]`; `no-new-privileges: true`; `tmpfs: [/tmp, /run]`; non-root user `10001:10001`; no published ports)
- Created `compose/compose.t0.yml`: Leaky baseline positive control (flat bridge network, shared `/shared` volume, no container hardening, positive control leaks)
- Created `cairn.admin_client`: Unix domain socket admin client communicating with `/run/cairn/admin.sock` via `docker compose exec -T switchboard` per DEC-3
- Created `cairn.switchboard.runner`: Dual server hosting tenant API on internal TCP port 8000 and referee admin API on UDS `/run/cairn/admin.sock`
- Created `cairn.switchboard.remote_adapters`: RemoteBlueGuard and RemoteModelEngine HTTP client adapters
- Created `cairn.tenants.blue.service`: Blue guard HTTP service running inside blue container on port 8100
- Created `cairn.model.service`: Model HTTP service running inside model container on port 8200
- Created `cairn.tenants.netprobe`: In-container socket probe checking target reachability and external egress
- Created `cairn.auditor.matrix`: Host-side coordinator auditing N x N reachability matrix and external egress (Conformance Test C3)
- Created `cairn.referee.docker_ctl`: Docker and Compose host controller
- Created `cairn.referee.doctor`: Doctor preflight verification module checking Docker, cgroups, matrix, and container security controls
- Created `cairn doctor` CLI subcommand supporting `--tier` and `--live`

**Verified by:**
- `make lint` → exit 0 (Ruff check clean, 54 files properly formatted)
- `make test` → exit 0 (27 passed in 0.45s)
- `make test-e2e` → exit 0 (4 passed in 2.70s):
  - `test_t1_matrix_and_egress`: 0 deviations; only `red->switchboard:8000`, `switchboard->blue:8100`, `switchboard->model:8200` are reachable; zero egress across all 4 containers
  - `test_t1_container_hardening_inspection`: verified `ReadonlyRootfs=True`, `CapDrop=['ALL']`, `User="10001:10001"`, `no_docker_sock=True`
  - `test_t1_live_doctor_preflight`: live doctor preflight returns PASS
  - `test_t1_live_attack_request`: real end-to-end request executed from inside `red` container to `switchboard` returns 200 with uniform envelope
- `cairn doctor --tier t1 --live` executed: passed with exit code 0
- `cairn doctor --tier t0` executed: verified positive control flags reported

**Decisions:** (none new; followed DEC-2, DEC-3, DEC-7, DEC-11)

**Gate G2 (Internal networks):** ✅ GREEN — N×N matrix on T1 shows only allowed edges, 0 deviations, zero external egress.

**Next:** M4 — Auditor and probes (L1 cross-session probe, L3 token limit probe, L4 side channel timing probe, canary scanning, attestation collector)

---

## 19 Oct 2026 18:09 IST — M4: Gold-Team Auditor and Probes

**Done:**
- Created `cairn.auditor.l1_leak`: L1 cross-session and shared storage leak probe (positive control on T0)
- Created `cairn.auditor.l3_quota`: L3 token call limit (max_calls) and input size cap (>16 KB) enforcement probe
- Created `cairn.auditor.l4_timing`: L4 side-channel timing probe measuring cross-session prefix cache timing leakage using Welch's t-test with integer representation per DEC-19
- Created `cairn.auditor.canary`: Canary scanner checking emitted events and file directories for foreign/unregistered canaries
- Created `cairn.auditor.attestation`: Attestation collector gathering container image digests, config sha256s, and emitting `attestation.manifest`

**Verified by:**
- `make lint` → exit 0 (Ruff clean, 60 files formatted)
- `make test` → exit 0 (31 passed in 0.50s)
- `make test-e2e` → exit 0 (4 passed in 2.68s)
- Negative control on T0:
  - L1 probe finds the leak planted in `/shared` in T0 (`leak_detected = True`, `mechanism = "shared_storage_leak"`)
  - L4 probe detects prefix cache timing leakage in T0 (positive latency delta, Welch's t-statistic > 2.878, p < 0.01)
- Positive controls on T1:
  - L1 probe confirms zero leak in T1 (`leak_detected = False`)
  - L3 probe confirms token call budget and size cap enforcement (`budget_enforced = True`, `size_cap_enforced = True`)
  - L4 probe confirms timing distribution is flat in T1 (`delta_ms = 0`, p >= 0.01)
- Canary scan confirms clean logs and detects injected foreign tokens
- Attestation collector freezes manifest and emits `attestation.manifest` into evidence store

**Decisions:** (followed DEC-10, DEC-12, DEC-14, DEC-17, DEC-19)

**Gate G3 (Auditor negative controls):** ✅ GREEN — L1 probe finds the leak planted by Blue in T0; L4 probe detects prefix cache timing leakage in T0 (p < 0.01).

**Next:** M5 — Validity Engine and Certificates (I1-I9 evaluation, pure function from events, status, receipts generation, cairn verify integration)
