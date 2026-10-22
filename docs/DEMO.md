# CAIRN Video Demo Script & Walkthrough Guide

> **Target Duration:** ≤ 3 minutes (180 seconds)
> **Audience:** Hack in Hills '26 Round 2 Evaluators & Peer Reviewers
> **Primary Command:** `make demo` (executes automated end-to-end assurance workflow)

---

## Overview for the Presenter

This script guides you through recording a concise, technically defensible demonstration of CAIRN.

Before recording:
- Ensure Docker is running on your machine.
- Have a clean terminal window open at the repository root.
- The demo runs automatically in under 60 seconds via `make demo`.
- Have a web browser ready if you wish to show the generated HTML report at the end.

---

## Scene 1: Introduction & Architecture Context (0:00 – 0:30)

**On-Screen Action:**
Terminal is visible at repository root. You type `make demo` and press Enter. The terminal displays the starting header:
```text
======================================================================
CAIRN DEMO — STARTING AUTOMATED END-TO-END ASSURANCE WORKFLOW
======================================================================
```

**Spoken Narration:**
> "Welcome to our demonstration of CAIRN—Cryptographic Assurance and Isolation for Red-Team Networks.
>
> Today, evaluations of AI defenses face a fundamental credibility issue: benchmarks claim that testing is isolated, but they rarely prove it. Red-team prompts can leak across shared storage, infer defense policies through timing side channels, or bypass network boundaries.
>
> CAIRN's central thesis is simple: isolation must not merely be claimed—it must be actively attacked, statistically measured, and cryptographically verified.
>
> In this demo, we run CAIRN's automated assurance workflow. Note that this prototype uses `SimEngine`, a calibrated, deterministic simulated model backend. This allows us to rigorously validate our test harness and measurement probes under controlled conditions before deploying to production LLM infrastructure."

---

## Scene 2: Leaky Baseline vs. Hardened Tier (0:30 – 1:10)

**On-Screen Action:**
Watch Step 1/6 and Step 2/6 execute in the terminal:
```text
[Step 1/6] Running T0 Leaky Baseline Positive Control (r_demo_t0_...)...
  T0 run completed: runs/r_demo_t0_...

[Step 2/6] Running T1 Hardened Isolation Tier (r_demo_t1_...)...
  T1 run completed: runs/r_demo_t1_...
```

**Spoken Narration:**
> "Step 1 executes Tier 0, our leaky baseline positive control.
> T0 represents a naive setup: flat networking, shared storage volumes, and an unisolated cache. If an audit harness cannot reliably catch a deliberately broken baseline, it cannot be trusted to certify a hardened system.
>
> On T0, our probes flag immediate leaks:
> - The L1 prefix-cache probe detects cache timing differences with an AUC of 1.00 and high token recovery.
> - The L3 probe detects output size and latency leakage.
> - The L4 probe finds planted canary tokens in shared storage.
> - And our live container network probe detects ten illegal communication paths and internet egress.
>
> In Step 2, CAIRN runs Tier 1, our hardened isolation tier.
> Here, live container networking enforces isolated bridge networks with zero egress. The model prefix cache is cryptographically salted per session, and Switchboard quantizes response release timing.
>
> Under T1, the L1 and L3 probes drop to an AUC of 0.50—reported as `NO_SIGNAL_AT_POWER`. This means no side-channel leakage was detected at our evaluated statistical power of 200 trials. No foreign canaries were found in the inspected mount, and container reachability had zero deviations."

---

## Scene 3: Environmental Interference & Fault Handling (1:10 – 1:40)

**On-Screen Action:**
Watch Step 3/6 execute in the terminal:
```text
[Step 3/6] Running Fault Injection Run (blue_timeout@f_005, r_demo_fault_...)...
  Fault injection run completed: runs/r_demo_fault_...
```

**Spoken Narration:**
> "What happens when defenses slow down or infrastructure experiences heavy load?
>
> In Step 3, we simulate an environmental fault: we inject an intentional defense timeout on attack finding `f_005` while running a background CPU burner.
>
> In a fragile harness, an internal timeout might fail open, allowing an uninspected adversarial prompt through to the model—which T0 demonstrated as a positive control.
>
> In CAIRN Tier 1, the Switchboard fails closed. When the deadline expires, it releases a generic refusal envelope, logs an infrastructure timeout event, and quarantines finding `f_005`. Crucially, only the affected finding is quarantined; the remaining eleven findings remain intact and certified."

---

## Scene 4: Cryptographic Receipts & Tampering Rejection (1:40 – 2:20)

**On-Screen Action:**
Watch Step 4/6 and Step 5/6 execute in the terminal:
```text
[Step 4/6] Verifying Untouched T1 Finding Receipt...
  PASS: Untouched receipt receipt_f_001.json verified successfully: Receipt verification succeeded

[Step 5/6] Executing Tamper Demo (C8 Byte Mutation)...
  PASS: Tampered receipt was successfully rejected: Step 2 failed: Event seq 1 hash mismatch: recorded ... != computed ...
```

**Spoken Narration:**
> "In Step 4, CAIRN verifies an untouched finding receipt.
> Each receipt is a self-contained JSON artifact containing the test manifest, tenant commitments, raw evidence events, and RFC 6962 Merkle inclusion proofs.
>
> The independent verifier executes five mathematical verification steps:
> 1. Verifying the Ed25519 signature over the checkpoint.
> 2. Verifying the SHA-256 event hash chain.
> 3. Verifying the Merkle inclusion proof up to the signed root.
> 4. Verifying commit-reveal nonces for both Red and Blue tenants.
> 5. Recomputing the validity certificate directly from the raw events.
>
> Step 4 passes cleanly.
>
> In Step 5, we demonstrate tampering detection. The demo creates a copy of the receipt and injects an altered field (`tampered: true`) into the body of the first event.
>
> Notice the exact terminal output: verification immediately halts at Step 2. Because the SHA-256 hash of the modified body does not match the recorded event hash, the verifier rejects the receipt and exits with code 1. Any alteration to events, proofs, or signatures is caught mathematically."

---

## Scene 5: Offline Witness & Viewing Results (2:20 – 2:45)

**On-Screen Action:**
Terminal displays Step 6 completion and final checkpoint details:
```text
[Step 6/6] Reading Offline Witness Checkpoint Hashes & Writing docs/RESULTS.md...
  T1 Signed Checkpoint Root: <root_hash>
  T1 Checkpoint Run ID:      r_demo_t1_<timestamp>
  T1 Checkpoint Tree Size:   11063
  Wrote comprehensive comparison to: docs/RESULTS.md
```
*(Optional: Open the generated HTML report in a browser or view `docs/RESULTS.md` in your editor).*

**Terminal Commands for Presenter (Optional inspection):**
```bash
# View the compiled markdown summary
cat docs/RESULTS.md

# Or open the self-contained HTML assurance report in your browser:
# (Replace the run ID below with the T1 run ID printed in your terminal output)
xdg-open runs/r_demo_t1_<timestamp>/report.html
```

**Spoken Narration:**
> "At Step 6, the referee outputs an Ed25519-signed Merkle checkpoint root. This root acts as a compact, immutable witness for all eleven thousand recorded events, suitable for cross-signing or public transparency logs.
>
> The demo automatically compiles the recorded run data into `docs/RESULTS.md`.
>
> Presenters can also open `report.html` located inside the generated T1 run directory. This offline report displays the full validity matrix, invariant evaluations I1 through I9, probe distributions, and the residual risk register."

---

## Scene 6: Conclusion & Honest Limitations (2:45 – 3:00)

**On-Screen Action:**
Return to terminal or show a summary slide with the project thesis:
- *Active positive controls (T0)*
- *Cryptographically signed receipts (RFC 6962 Merkle)*
- *Bounded side-channel measurement (`NO_SIGNAL_AT_POWER`)*
- *Fail-closed assurance under fault injection*

**Spoken Narration:**
> "To summarize: CAIRN demonstrates that generative AI safety benchmarks can be held to the same cryptographic and operational rigor as secure distributed systems.
>
> Our prototype proves that side channels can be actively measured, network boundaries verified inside live containers, and benchmark findings certified without blind trust.
>
> While our current probe numbers reflect a simulated model backend rather than production LLM hardware, the underlying cryptographic ledger, fail-closed referee, and verification pipeline provide a defensible foundation for trustworthy AI evaluation.
>
> Thank you."

---

## Quick Reference for Presenters

| Scene | Timestamp | Key On-Screen Element | Key Takeaway |
| :--- | :--- | :--- | :--- |
| **1. Intro** | 0:00–0:30 | Terminal starting `make demo` | AI safety benchmarks require verified, measured isolation; `SimEngine` disclosure. |
| **2. T0 vs T1** | 0:30–1:10 | Steps 1/6 and 2/6 completing | T0 catches leaks (positive control); T1 shows `NO_SIGNAL_AT_POWER` and 0 network deviations. |
| **3. Faults** | 1:10–1:40 | Step 3/6 completing | Defense timeout under CPU stress fails closed; only `f_005` is quarantined. |
| **4. Receipts** | 1:40–2:20 | Steps 4/6 and 5/6 output | Untouched receipt verifies; Step 2 hash mismatch immediately rejects altered event. |
| **5. Witness** | 2:20–2:45 | Step 6/6 and `report.html` | Signed checkpoint root logged; results written to `docs/RESULTS.md`; report opens offline. |
| **6. Closing** | 2:45–3:00 | Project summary slide/terminal | Honest prototype limitations; cryptographic assurance replaces unverified trust. |
