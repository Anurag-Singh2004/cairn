# CAIRN — Blind-by-Design, Measured, Signed Isolation for Adversarial AI Safety Testing

> **Status: scaffold only (M0).** No functional code exists yet. This section will be updated as milestones are completed.

## What is CAIRN?

CAIRN is a test-infrastructure prototype in which a RED team (attack agent), BLUE team (defense filters) and MODEL (client LLM) run concurrently in controlled zones. CAIRN attacks its own isolation, measures leakage, and issues per-finding validity certificates with independently verifiable evidence.

**Central thesis:** Isolation should not merely be claimed. It should be attacked, measured, and independently verified.

## Quickstart

```bash
# 1. Clone and set up
git clone <repo-url> && cd cairn
make setup

# 2. Run linter and unit tests
make lint
make test

# 3. Run the full demo (requires Docker)
make demo

# 4. Verify a receipt offline
make verify RECEIPT=runs/<run-id>/receipts/<finding>.json

# 5. View the generated report
open runs/<run-id>/report.html
```

## Honest limits

- This is a hackathon prototype, not production software.
- SimEngine results are labelled `SIMULATED` — they validate the harness, not real-engine behaviour.
- "No leak detected at the stated test power" does not mean "no leak exists."
- Signatures and tamper-evident logs show integrity relative to a key; they do not prove the system is free of vulnerabilities.
- See `docs/THREAT_MODEL.md` for the full guarantee and residual-risk register.

## Planned / not implemented

- Real-engine (llama.cpp) backend — depends on spike S1 result
- gVisor (T2) tier
- AES-256-GCM vault encryption
- Live dashboard
- L3 verdict-fingerprint probe
- See `PROGRESS.md` for current status

## Project structure

See `context.md` §11 for the directory layout and `flow.md` for the build plan.

## Event

Hack in Hills '26 · Problem 04 (Bayora) · Round 2 prototype
