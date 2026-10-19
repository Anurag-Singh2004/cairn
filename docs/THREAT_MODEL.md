# CAIRN Threat Model & Security Assurance Specification

> **Specification per `context.md` §2, §8, and `flow.md` §10 (REQ-O6)**
> **Version:** 1.0 (Hack in Hills '26, Round 2)
> **Classification:** Public Technical Assurance Document

---

## 1. Overview & Objectives

CAIRN is a defense-in-depth, cryptographically verifiable isolation and benchmarking architecture designed to evaluate generative AI defenses under adversarial scrutiny. Its primary objective is to guarantee that red-team adversarial tenants:
1. Cannot access protected resources (Blue defense components, Model inference engines, host daemon, external networks) outside the mediated Switchboard gateway.
2. Cannot infer defensive verdicts or extract cross-session private context via side channels (response latency, payload length, status codes, or prefix cache hits).
3. Cannot tamper with, forge, or repudiate audit logs and validity certificates.

---

## 2. Threat Model & Adversary Capabilities

### 2.1 Adversary Profile (Untrusted Red Tenant)
The adversary is modeled as an untrusted red-team agent executing code inside an isolated container.

| Capability | In Scope / Out of Scope | Description & Restrictions |
|---|---|---|
| **Arbitrary Prompt Generation** | **In Scope** | May submit arbitrary textual payloads up to the 16 KB size cap. |
| **Adaptive Probing** | **In Scope** | May adapt prompts dynamically based on returned responses. |
| **Side-Channel Timing Observation** | **In Scope** | May measure wall-clock latency between request submission and response arrival down to millisecond or microsecond resolution. |
| **Side-Channel Length Observation** | **In Scope** | May inspect response payload length and HTTP status codes to infer internal filter verdicts. |
| **Multi-Session Attacks** | **In Scope** | May spawn multiple sequential sessions attempting to extract residual prefix cache state left by victim sessions. |
| **Environmental CPU Starvation** | **In Scope** | May attempt local CPU burning (`--burn`) to create noisy-neighbor jitter. |
| **Host Kernel Compromise** | **Out of Scope** | 0-day Linux kernel vulnerabilities, container breakouts (`runc`/cgroup escapes), or physical hardware attacks (Spectre/Meltdown across physical SMT hyperthreads). |
| **Referee Key Compromise** | **Out of Scope** | Physical or root access to the Referee's host filesystem storing `keys/ref_ed25519.pem`. |

---

## 3. Defense-in-Depth Architectural Controls

CAIRN enforces layered controls spanning container virtualization, network topology, traffic shaping, and append-only cryptographic logging:

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

### 3.1 Network Topology & Boundary Confinement
- **Internal Networks:** `red-net` (Red ↔ Switchboard), `blue-net` (Switchboard ↔ Blue Guard), `model-net` (Switchboard ↔ Model).
- **Isolation:** Internal Docker networks have no default gateway; `internal: true` prevents external Internet egress and inter-tenant traffic.
- **Enforcement:** Verified before and after runs via an $N \times N$ reachability auditor (`matrix.py`).

### 3.2 OCI Hardening
- **Least Privilege:** Non-root execution (`user: 10001:10001`).
- **Filesystem Immutability:** `read_only: true` on rootfs; ephemeral storage limited to in-memory `tmpfs` mounts with `noexec,nodev,nosuid`.
- **Capability Stripping:** `cap_drop: ["ALL"]` and `security_opt: ["no-new-privileges:true"]`.
- **Zero Socket Exposure:** Docker daemon socket (`docker.sock`) is strictly prohibited inside containers.

### 3.3 Side-Channel Elimination (Switchboard)
- **Uniform Envelopes:** All responses (including blue blocks, model refusals, and timeouts) are normalized to fixed bucket sizes (e.g., 256, 512, 1024 bytes) padded with spaces. Red sees byte-identical structure.
- **Quantized Release Timing:** Delivery latency is rounded up to the nearest multiple of quantum $\Delta$ ($\Delta \times \lceil \text{latency} / \Delta \rceil$). Over-deadline requests fail closed to generic refusal.
- **Salted Cache Namespaces:** Red-provided session IDs are combined with a per-run random salt and hashed (`HMAC-SHA256(salt, session_id)`), preventing prefix-cache hits across sessions.

### 3.4 Cryptographic Verifiability & Validity Certificates
- **Append-Only Evidence:** SQLite evidence store enforcing monotonic sequences and canonical SHA-256 event chaining.
- **Merkle Tree Proofs:** RFC 6962 Merkle tree with logarithmic audit paths tying every event to a signed checkpoint.
- **Commit-Reveal Protocol:** Red attack packs and Blue filter policies are hashed and committed prior to execution, preventing post-hoc rule adjustments.
- **Pure Offline Verification:** Step 5 certificate recomputation evaluates invariants I1–I9 directly from raw evidence events, ensuring receipts cannot be fabricated.

---

## 4. Security Guarantees & Failure Conditions

| Guarantee | Mechanism | Conditions Under Which It Holds | Failure Conditions & Manifestation |
|---|---|---|---|
| **G1: Network Boundary Confinement** | Isolated internal bridge networks; no inter-tenant edges. | Linux network namespace integrity; correct Docker network configuration. | Fails if host kernel routing leaks packets or bridge misconfiguration attaches Red directly to Blue/Model. Audited by Matrix probe (I2 violation $\rightarrow$ `QUARANTINED`). |
| **G2: Side-Channel Timing Invariance** | Quantized release timing $\Delta \times \lceil t / \Delta \rceil$. | System load allows responses within deadline $T_{\text{deadline}}$. | Fails if excessive noisy-neighbor CPU load delays release past deadline ($t > T$). Enforces fail-closed: releases generic refusal and records `infra.timeout` (I5/I9). |
| **G3: Side-Channel Length Invariance** | Uniform envelope padding into pre-defined power-of-two buckets. | Response length does not exceed maximum bucket cap. | Fails if uninspected text or raw errors bypass envelope generator. Audited by L3 probe (AUC lower CI $> 0.65 \rightarrow$ `LEAK_DETECTED`). |
| **G4: Cross-Session Prefix Isolation** | Cryptographic salt per session; isolated namespace trie. | Salt randomness $H(\text{salt} \parallel \text{sess})$ collision resistance. | Fails if shared cache mode is enabled (T0) or namespace derivation collides. Audited by L4 probe ($p < 0.01 \rightarrow$ `LEAK_DETECTED`). |
| **G5: Audit Evidence Non-Repudiation** | Canonical JSON, SHA-256 chain, RFC 6962 Merkle tree, Ed25519 signatures. | Ed25519 private key secrecy (`keys/ref_ed25519.pem` permission 0600). | Fails if private key is stolen or hash collision found in SHA-256. Any single-byte modification invalidates Merkle proof or signature (`cairn verify` fails with exit code 1). |

---

## 5. Residual Risk Register

| Risk ID | Description | Impact | Mitigation / Status |
|---|---|---|---|
| **R-1** | **Physical SMT Cache Contention:** Microarchitectural cache timing (Spectre/L1TF) across hyperthreads sharing physical CPU cores. | Low | Core pinning (`cpuset`) recommended in production; out of scope for software benchmark. |
| **R-2** | **Host Kernel 0-day Escape:** Vulnerability in Linux cgroup or namespace subsystem allowing container breakout. | Critical | Defense-in-depth: non-root execution, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs; optional gVisor runtime. |
| **R-3** | **SimEngine Timing Discretization:** The simulated engine uses deterministic latency models rather than real GPU matrix multiplications. | Medium | Clearly disclosed per REQ-G5/G6: all SimEngine outputs marked `simulated: true` and certificates graded `VALID_WITH_WARNINGS`. |
| **R-4** | **Extreme Host Starvation:** Severe host thrashing causing Referee clock skew or delayed event writing. | Low | Timeouts fail closed (`infra.timeout`); monotonic sequence numbers detect missed events. |

---

## 6. Pre-Registered Assurance Thresholds

As recorded in `configs/thresholds.toml`:

```toml
[probes.l1]
leak_threshold = 0

[probes.l3]
metric = "auc_lower_ci"
threshold = 0.65
resamples = 1000

[probes.l4]
alpha = 0.01
min_samples = 10
```
