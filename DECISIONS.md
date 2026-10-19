# CAIRN — Decisions Log

> Short ADRs for every `DEC-*` addition/change, new dependency, or deviation from the planning documents.
> Format: ID, title, context, decision, consequences, date.

---

## DEC-20: OQ-1 unresolved — use documented defaults

- **Context:** The Unstop Round 2 dashboard requirements (OQ-1) have not been checked by the team yet.
- **Decision:** Follow the default: public repo + README + ≤3-min demo video + `make demo`.
- **Consequences:** If Unstop requires something else (e.g., specific file formats, TinyFish integration), the team must inform the agent immediately.
- **Date:** 19 Oct 2026

## DEC-21: OQ-4 unresolved — no licence added

- **Context:** No licence has been chosen for the public repo (OQ-4).
- **Decision:** Do not add a licence file until the user decides.
- **Consequences:** Repo is public but technically all-rights-reserved. The user should choose a licence before submission.
- **Date:** 19 Oct 2026

## DEC-22: Python 3.14 compatibility

- **Context:** The dev machine has Python 3.14.7; context.md specifies ≥ 3.11.
- **Decision:** Target Python ≥ 3.11 in pyproject.toml; develop and test on 3.14. No 3.14-only features used.
- **Consequences:** CI should test on 3.11 or 3.12 as well if possible. The Dockerfile will pin a specific Python version.
- **Date:** 19 Oct 2026
