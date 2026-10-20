# CAIRN — Cryptographic Assurance & Isolation for Red-Team Networks

[![Tests](https://img.shields.io/badge/tests-74%20passed%2C%201%20skipped-brightgreen.svg)]()
[![Lint](https://img.shields.io/badge/ruff-passing-brightgreen.svg)]()
[![Type](https://img.shields.io/badge/python-3.11%2B%20%7C%203.14-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Hackathon](https://img.shields.io/badge/Hack%20in%20Hills%20'26-Round%202-orange.svg)]()

> **Central Thesis:** Isolation must not merely be claimed. It must be actively attacked, statistically measured, and cryptographically verified.

CAIRN is a defense-in-depth, blind-by-design benchmarking and test harness designed to evaluate generative AI defenses under adversarial scrutiny. A **Red Team** (attack agent), **Blue Team** (defense guardrails), and **Model Engine** run in isolated security zones. CAIRN continuously attacks its own isolation, measures side-channel leakage across storage and timing, and generates self-contained cryptographic receipts with independently verifiable RFC 6962 Merkle inclusion proofs.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------------+
|                                    HOST SYSTEM                                          |
|                                                                                         |
|   +-----------------------+              +------------------------------------------+   |
|   |   Auditor & Referee   |  (UDS Sock)  |              Switchboard Gateway         |   |
|   |   (Ed25519 / Merkle)  |<============>|  - AuthZ Token Verification              |   |
|   +-----------------------+              |  - Per-Session Salted Namespace          |   |
|               ^                          |  - Uniform Envelope Space Padding        |   |
|               |                          |  - Quantized Release Timing Δ            |   |
|         (Attestations)                   +------------------------------------------+   |
|               |                               ^                |             |          |
|               |                               | (red-net)      | (blue-net)  | (model)  |
|               |                               v                v             v          |
|   +-----------------------+           +---------------+ +------------+ +------------+   |
|   |    Hardware / Host    |           |   Red Agent   | | Blue Guard | | Model Svc  |   |
|   |  - Read-Only Rootfs   |           | (Adversarial) | |  (Filter)  | |  (Sim/LLM) |   |
|   |  - Non-Root (10001)   |           +---------------+ +------------+ +------------+   |
|   |  - Cap Drop ALL       |                   ^               ^             ^           |
|   +-----------------------+                   +---------------+-------------+           |
|                                                       NO DIRECT EDGES                   |
+-----------------------------------------------------------------------------------------+
```

### Key Security Controls
1. **Isolated OCI Tier (T1):** Hardened Docker Compose tier with isolated internal bridge networks (`red-net`, `blue-net`, `model-net`), read-only root filesystems, dropped capabilities (`cap_drop: ALL`), non-root execution (`10001:10001`), and zero external internet egress.
2. **Leaky Positive Control (T0):** A deliberately unhardened baseline with flat networking and shared storage (`/shared`) to prove the auditor probes function correctly.
3. **Switchboard Gateway:** Mediates all prompt traffic, pads responses into uniform space-padded buckets (DEC-13), quantizes release latency ($\Delta \times \lceil t / \Delta \rceil$), and salts model prefix-cache namespaces (`HMAC-SHA256(salt, session_id)`).
4. **Statistical Side-Channel Probes:**
   - **L1 Prefix-Cache Timing Probe:** Evaluates hit/miss latency AUC (Mann-Whitney) with bootstrap 95% CI (leak if lower CI $\ge 0.65$) and candidate token recovery rate (leak if $\ge 5\times\text{chance}$, $N=200$ trials/class) to detect cross-session cache timing side channels.
   - **L3 Verdict Fingerprint Probe:** Evaluates single-feature rank AUC with 1000 bootstrap resamples (leak if lower CI $\ge 0.65$, $N=15$/class) to detect if response size, latency, or status code leaks defensive block vs refusal decisions.
   - **L4 Storage & Env Enumeration Probe:** Detects foreign tenant canary tokens across inspected container filesystems, the tested `/shared` mount, and enumerated environment variables.
5. **Cryptographic Receipts & Pure Certificate Recomputation:** Self-contained JSON receipts contain raw evidence events chained by SHA-256 hashes, RFC 6962 Merkle inclusion proofs to an Ed25519-signed checkpoint, and commit-reveal nonces. An independent verifier recomputes validity certificates offline directly from events.

---

## 5-Command Quickstart

```bash
# 1. Setup virtual environment and dependencies
make setup

# 2. Run linter and full unit/integration test suite
make lint && make test

# 3. Verify Docker environment and container isolation
make doctor

# 4. Execute the complete end-to-end assurance demo
make demo

# 5. Verify an untouched receipt or test tamper rejection
make verify RECEIPT=runs/r_demo_t1/receipts/receipt_f_001.json
```

---

## CLI Reference

CAIRN provides a unified command-line tool `cairn` (or `python -m cairn.cli`):

| Command | Usage | Description |
|---|---|---|
| `cairn keygen` | `cairn keygen --out keys/` | Generate Ed25519 referee keypair with 0600 file permissions. |
| `cairn doctor` | `cairn doctor --tier t1 --live` | Audit host environment, cgroup, Docker, and run $N \times N$ matrix. |
| `cairn run` | `cairn run --tier t1 --pack data/attack_packs/demo.json` | Execute a complete benchmark run and generate evidence. |
| `cairn certify` | `cairn certify --run <run-id>` | Evaluate validity invariants I1–I9 and emit final signed checkpoint. |
| `cairn verify` | `cairn verify <receipt.json>` | Perform 5-step cryptographic verification of a finding receipt. |
| `cairn verify-run` | `cairn verify-run --run <run-id>` | Verify all receipts within a benchmark run directory. |
| `cairn report` | `cairn report --run <run-id>` | Generate self-contained offline `report.html` (zero external CDNs). |
| `cairn demo` | `cairn demo` | Execute automated end-to-end walkthrough (T0, T1, faults, tamper). |

---

## Benchmark Results (T0 vs T1 Contrast)

Generated directly from recorded benchmark runs (see `docs/RESULTS.md`):

| Property | Metric & Threshold | T0 Leaky Baseline | T1 Hardened Isolation | Threshold / Target | Result Status |
|---|---|---|---|---|---|
| **L1 Prefix-Cache Timing** | Hit/Miss AUC; leak if lower 95% CI $\ge 0.65$ OR recovery $\ge 5\times\text{chance}$ ($N=200$) | `LEAK_DETECTED` (AUC: 1.00, CI: [1.00, 1.00], recovery: 100.0% vs chance 10.0%, N=200) | `NO_SIGNAL_AT_POWER` (AUC: 0.50, CI: [0.50, 0.50], recovery: 10.5% vs chance 10.0%, N=200) | No signal: lower CI $< 0.65$ AND recovery $< 5\times\text{chance}$ | **NO_SIGNAL_AT_POWER** |
| **L3 Verdict Fingerprint** | Single-feature AUC; leak if lower 95% CI $\ge 0.65$ ($N=15$/class) | `LEAK_DETECTED` (AUC: 1.00, CI: 1.00) | `NO_SIGNAL_AT_POWER` (AUC: 0.50, CI: 0.50) | No signal: lower CI $< 0.65$ | **NO_SIGNAL_AT_POWER** |
| **L4 Storage & Env Enum** | Foreign canary search in tested `/shared` mount & enumerated environment | `LEAK_DETECTED` (Found foreign canary `canary_blue_99aa88bb` & planted misconfig in `/shared/blue_policy_leak.txt`) | `NO_SIGNAL_AT_POWER` (No foreign canaries detected in tested `/shared` mount or enumerated environment variables) | No foreign canaries | **NO_SIGNAL_AT_POWER** |
| **C3 Matrix Reachability** | $N \times N$ allowed topology across services & egress | `DEVIATIONS` (10 deviations) | `ENFORCED` (0 deviations) | 0 deviations | **ENFORCED** |
| **Fault Handling** | Injected timeout (`--inject-fault blue_timeout@f_005`) | **Fail-Open** (false `BYPASS` quarantined via I9) | **Fail-Closed** (`BLOCKED` + `infra.timeout`, finding quarantined) | Fail closed | **ENFORCED** |

---

## Honest Limitations

Per `context.md` §16 and `flow.md` §10:
- **SimEngine Disclosures:** Runs use `SimEngine` (a deterministic prefix-trie latency model) to test the test harness itself. All SimEngine outputs are explicitly marked `simulated: true` and certificates receive `VALID_WITH_WARNINGS`.
- **Negative Finding Interpretation:** "No leak detected at stated power" (`NO_SIGNAL_AT_POWER`) proves only that no signal was observed at the evaluated sample sizes ($N=200$ trials per class for L1 prefix-cache timing, $N=15$ observations per class for L3 verdict fingerprinting, and the container `/shared` mount and environment variables inspected for L4) on this host—not that the system is mathematically invulnerable or that no leakage exists under higher sample sizes or physical hardware execution.
- **Scope Limits:** Kernel-level 0-days, physical side channels across shared SMT CPU threads (Spectre/Meltdown), and referee private key theft are out of scope. See `docs/THREAT_MODEL.md` for the complete residual-risk register.

---

## Project Structure

```
cairn/
├── configs/               # Tier configurations (t0.toml, t1.toml, thresholds.toml)
├── compose/               # Dockerfile and compose definitions (compose.t0.yml, compose.t1.yml)
├── data/                  # Synthetic attack packs, blue filter policies, simulation rules
├── docs/                  # Architecture & verification documentation
│   ├── THREAT_MODEL.md    # Threat model, adversary capabilities, and residual risks
│   ├── DEMO.md            # 3-minute video walkthrough script
│   └── RESULTS.md         # Machine-generated benchmark comparison results
├── src/cairn/             # Core implementation
│   ├── auditor/           # Probes (l1_leak, l3_fingerprint, l4_timing, matrix, canary, faults)
│   ├── common/            # Canonical JSON, float rejection, IDs, hashing, wall clock
│   ├── crypto/            # Merkle tree, Ed25519 keys, tokens, commit-reveal, AES-GCM vault
│   ├── model/             # SimEngine deterministic caching and timing
│   ├── referee/           # Validity engine, evidence store, receipt generator, verifier, runner
│   ├── switchboard/       # Uniform envelope, quantized release, session manager, FastAPI app
│   └── tenants/           # Blue defense guard, red agent, in-container network probe
└── tests/                 # Unit, integration, and Docker end-to-end test suites
```

---

## Event Details

- **Hack in Hills '26** · Problem 04 (Bayora) · Round 2 Submission
- **Deadline:** Saturday, 24 October 2026, 11:59 PM IST
- **Repository:** Fully autonomous test-driven implementation (Milestones M0 through M7).
