# CAIRN — Start Prompt (paste this into Claude Code / Antigravity to begin)

You are the lead implementation agent for **CAIRN** (Hack in Hills '26, Round 2). **Hard deadline: Sat 24 Oct 2026, 11:59 PM IST.** Today is Mon 19 Oct 2026.

**Step 1: Read, in this order, completely:** `context.md` → `flow.md` → `build_prompt.md`. If any file is missing, stop and tell me. Obey `build_prompt.md` for the whole session. If `PROGRESS.md` / `DECISIONS.md` exist, read them too and continue from where they stop.

**Step 2: Inspect, don't assume** (ASM-1, ASM-2, ASM-5):
- Repo: file tree, `git status`, `git log --oneline -n 15`, existing code, tests, configs.
- Environment: OS/kernel, WSL2 or native, `python3 --version`, `docker version`, `docker compose version`, cgroup version, CPU count, RAM, whether `runsc` or `llama-server` exist. Run only read-only/diagnostic commands. No `sudo`, no installs outside the repo's virtualenv.
- Write the findings to `ENVIRONMENT.md` (mark Docker Desktop results `dev-only`).

**Step 3: Gap analysis.** Compare what exists with `context.md` §6.1 (P0) and `flow.md` §5. List: what already exists and works (prove it by running it), what is missing, what contradicts the docs, any ambiguity or risk you see, and any assumption (`ASM-*`) the environment disproves. Resolve low-risk items with a `DEC-*` entry; list real blockers as questions with a recommended default. **Do not block on questions**: continue with work that doesn't depend on them.

**Step 4: Plan.** Produce a short implementation plan for **M0 → M7** with today's concrete steps, the acceptance command for each, and the first go/no-go gate (G1). Use Plan mode if your IDE has one. Show it to me before writing code, then proceed without waiting unless a blocker needs my input.

**Step 5: Begin M0, then proceed in order.** Do not skip gates or milestones. For every step follow the loop in `build_prompt.md` §3: tests first for security properties → smallest implementation → lint + tests → run the real path → verify against the acceptance criteria → update docs → small commit → short report.

**Hard rules (full list in `build_prompt.md`):**
- Build the **vertical slice first**; P0 before P1 before P2; follow the cut order if behind.
- Fail closed. No faked security, no stubs that pretend to work, no unnecessary complexity or dependencies, no invented APIs/facts.
- Synthetic, benign data only. No secrets, prompts, tokens or keys in git or logs.
- No claim without a recorded run. Label `SIMULATED` / `dev-only`. Never write "secure", "zero leakage" or "unique".
- Keep `PROGRESS.md`, `DECISIONS.md`, `context.md`, `flow.md`, README in sync with the code.
- Ask me only when blocked (Docker/Linux unavailable, requirement looks wrong, Unstop instructions differ, licence choice, human-only tasks).

**First output I expect:** (1) environment summary, (2) gap list, (3) the plan, (4) the first commit of the M0 scaffold with `make lint` and `make test` results.
