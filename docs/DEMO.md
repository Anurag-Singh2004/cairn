# CAIRN Video Demo Script & Walkthrough Guide

> **Target Duration:** ≤ 3 minutes  
> **Audience:** Hack in Hills '26 Round 2 Evaluators & Security Engineers  
> **Command:** `make demo` (or `cairn demo`)

---

## Act 1: The Problem — Leaky Baseline (0:00 - 0:40)

**Visual:** Terminal showing execution of `make demo` or `cairn run --tier t0`. Terminal highlights positive control detection.

**Narration / Script:**
> "Generative AI security benchmarks today face a fundamental assurance crisis: red-team tenants can bypass filters, leak data across shared volumes, and infer defensive rules through latency and envelope side channels.
>
> In CAIRN, we don't just assert security—we prove it. We start with Tier 0: our leaky baseline positive control. 
> Notice how CAIRN's automated auditor immediately flags the system:
> 1. The L1 prefix-cache timing probe detects cache timing leakage and token recovery with AUC 1.00.
> 2. The L3 verdict fingerprint probe detects response length and latency leaks with AUC 1.00.
> 3. The L4 storage probe discovers canaries exposed in shared storage.
>
> If a benchmark harness cannot catch a deliberately broken baseline, you cannot trust it when it says a system is safe."

---

## Act 2: Hardened Isolation — Tier 1 (0:40 - 1:20)

**Visual:** Terminal showing Step 2/6: Running T1 Hardened Isolation Tier.

**Narration / Script:**
> "Now we run Tier 1: CAIRN's hardened isolation tier.
> Here, four defense-in-depth controls take effect:
> - First, isolated internal container networks with zero external egress. Red cannot reach Blue or Model directly.
> - Second, non-root execution with read-only root filesystems and dropped capabilities.
> - Third, per-session cryptographic cache salting, eliminating cross-session cache hits.
> - And fourth, Switchboard's uniform envelopes and quantized release timing.
>
> Look at the auditor results:
> The L1 cache timing leakage drops to AUC 0.50—no signal observed at test power.
> The L3 verdict fingerprint drops to AUC 0.50—complete statistical noise.
> And the L4 storage probe finds no foreign canaries.
> Side channels are mitigated."

---

## Act 3: Environmental Interference & Fault Injection (1:20 - 1:55)

**Visual:** Terminal showing Step 3/6: Fault Injection run (`blue_timeout@f_005`) under `--burn` CPU stress.

**Narration / Script:**
> "What happens when infrastructure fails or adversaries try to starve the CPU?
> In Step 3, we inject a blue defense timeout on finding f_005 while burning background CPU.
> In a naive system, an infrastructure timeout might fail open, allowing unvetted attacks to reach the model.
> In CAIRN Tier 1, Switchboard fails closed: it releases a generic refusal envelope at the deadline, logs an infrastructure timeout event, and quarantines only that specific finding. The rest of the benchmark run remains intact and certified."

---

## Act 4: Cryptographic Receipts & Tamper Proof (1:55 - 2:35)

**Visual:** Terminal showing Step 4 & 5: Verifying untouched receipt (`cairn verify`), followed by the C8 byte mutation tamper demo.

**Narration / Script:**
> "Every finding produces a self-contained cryptographic receipt containing the manifest, commitments, raw evidence events, and RFC 6962 Merkle inclusion proofs.
>
> In Step 4, we verify an untouched receipt across 5 strict mathematical steps:
> 1. Checkpoint Ed25519 signature
> 2. SHA-256 event hash chain
> 3. Merkle inclusion proofs
> 4. Commit-reveal nonce verification
> 5. Pure certificate recomputation
>
> In Step 5, we test tampering. We mutate a single byte inside the evidence event.
> Instantly, Step 2 catches the altered event hash, Step 3 rejects the Merkle proof, and `cairn verify` fails closed with exit code 1.
> Receipts cannot be forged, reordered, or edited after the fact."

---

## Act 5: Offline Witness & Conclusion (2:35 - 3:00)

**Visual:** Terminal showing Step 6: offline witness checkpoint root, `docs/RESULTS.md` generated, and final HTML report opened.

**Narration / Script:**
> "Finally, CAIRN outputs an offline witness checkpoint root hash—ready to be cross-signed or posted to transparency logs—and writes a comprehensive, honest results report to `docs/RESULTS.md`.
>
> With reproducible positive controls, mathematically verified receipts, and strict fail-closed assurance, CAIRN turns AI security evaluation from an exercise in trust into an exercise in cryptographic verification.
> Thank you."
