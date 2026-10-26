# CAIRN Deployment Guide: Render Web Application & GitHub Actions Runner

This document details the live deployment architecture of **CAIRN** (Cryptographic Assurance & Isolation for Red-Team Networks).

---

## 1. Architecture Overview

CAIRN uses a decoupled architecture designed to deliver a publicly accessible, zero-maintenance evaluation experience without requiring a dedicated or self-hosted Linux machine:

```text
Evaluator's Browser
       │
       ▼ HTTPS
Render Web Service (`cairn-app`)
  ├── Single-Origin Interactive Frontend (`site/index.html`)
  ├── FastAPI Application (`src/cairn/webapp.py`)
  ├── Reference Results Engine (`docs/RESULTS.md` fallback)
  ├── Rate Limiter & Concurrency Lock (~10 min cooldown)
  └── Safe Allowlisted Artifact Streaming (`/api/jobs/{id}/artifacts.zip`)
       │
       ▼ Authenticated GitHub REST API (Fine-Grained PAT)
GitHub Actions (`.github/workflows/cairn-demo.yml`)
       │
       ▼ On-Demand Workflow Dispatch
Temporary GitHub-Hosted Ubuntu Runner (`ubuntu-latest`)
  ├── Clean checkout of repository
  ├── Python 3.12 environment setup
  ├── Docker Compose tier build & start
  ├── Full `make demo` execution (T0 leaky baseline vs T1 hardened tier)
  ├── Cryptographic receipt generation & offline verification
  ├── Tamper-rejection assertion (exit code 1 on mutated bytes)
  └── Allowlisted artifact bundle upload (`cairn-artifacts-<request_id>`)
       │
       ▼ Polled by Render API
Evaluator sees genuine workflow step progress and live updated metrics.
```

### Security & Isolation Boundaries
1. **Zero Client Secrets:** The browser never receives or handles GitHub credentials. All GitHub API operations (dispatch, run correlation, and artifact retrieval) happen strictly server-side on Render.
2. **Ephemeral Execution:** Heavy container execution and network probes occur entirely on temporary, disposable GitHub-hosted Ubuntu virtual machines.
3. **Artifact Whitelist:** Artifact downloads and cache extractions strictly enforce a whitelist (`.json`, `.md`, `.html`, `.txt`). Signing keys (`.key`, `.pem`), raw SQLite databases (`.db`, `.wal`, `.shm`), and environment files (`.env`) are strictly rejected.

---

## 2. GitHub Token Configuration

To allow Render to dispatch the benchmark workflow and retrieve artifacts, create a GitHub Personal Access Token (Fine-Grained recommended):

### Recommended: Fine-Grained Personal Access Token (Least Privilege)
1. Navigate to **GitHub Settings** → **Developer Settings** → **Personal Access Tokens** → **Fine-grained tokens**.
2. Click **Generate new token**.
3. **Token name:** `cairn-render-service`
4. **Expiration:** Select your preferred duration (e.g., 30 or 90 days).
5. **Repository access:** Select **Only select repositories** → choose `Anurag-Singh2004/cairn`.
6. **Permissions:**
   - **Actions:** `Read and write` (Required to trigger `workflow_dispatch` and inspect run status).
   - **Contents:** `Read-only` (Required to read workflow definitions and metadata).
7. Generate and copy the token (`github_pat_...`).

*(Alternatively, a classic token with `repo` or `workflow` scope can be used).*

---

## 3. Render Blueprint Setup

The repository defines the single Python Web Service in [render.yaml](file:///home/anurag/Projects/cairn/render.yaml):

```yaml
services:
  - type: web
    name: cairn-app
    runtime: python
    branch: main
    buildCommand: pip install -e .
    startCommand: uvicorn cairn.webapp:app --host 0.0.0.0 --port $PORT
    healthCheckPath: /api/health
    envVars:
      - key: GITHUB_REPOSITORY
        value: Anurag-Singh2004/cairn
      - key: GITHUB_WORKFLOW_FILE
        value: cairn-demo.yml
      - key: GITHUB_REF
        value: main
      - key: GITHUB_TOKEN
        sync: false
      - key: COOLDOWN_SECONDS
        value: "600"
```

> [!IMPORTANT]
> Do NOT create a Render Static Site for `site/`. The FastAPI service serves the interactive frontend and backend from the exact same origin at `GET /`.

### Deploying on Render:
1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** → **Blueprint**.
3. Connect your repository: `https://github.com/Anurag-Singh2004/cairn`.
4. Render will parse `render.yaml` and prompt for un-synced environment variables:
   - **`GITHUB_TOKEN`**: Paste your GitHub Personal Access Token.
5. Click **Apply**. Render will build and start `cairn-app`.
6. Once deployed, Render provides a public URL (e.g., `https://cairn-app.onrender.com`).

---

## 4. Operational Controls & Anti-Abuse Protections

To protect workflow quotas and maintain server stability on the public web:

| Control | Implementation | Purpose |
|---|---|---|
| **Single-Active-Run Lock** | Server queries GitHub Actions API for runs in `in_progress` or `queued` state. | Prevents parallel runner saturation across all users. |
| **Global Cooldown** | 10 minutes (`COOLDOWN_SECONDS=600`, configurable) measured from the newest completed run. | Enforces adequate spacing between intensive benchmark executions. |
| **Per-Client Rate Limiting** | In-memory sliding window: max 5 requests per 60 seconds per IP for `/api/jobs`. | Prevents spam or accidental button mashing. |
| **Execution Timeout** | GitHub Actions job specifies `timeout-minutes: 15`. | Terminates frozen or hanging jobs automatically. |
| **Reference Results Mode** | If `GITHUB_TOKEN` is unset or GitHub is unreachable, `/api/latest` serves `docs/RESULTS.md` labeled as **Historical Reference Run**. | Evaluators can immediately inspect verified baseline metrics without waiting. |

---

## 5. Free vs. Paid Plan Considerations

- **Free Tier:**
  - Render free web services spin down after 15 minutes of inactivity, causing a ~30–50s cold start on first visit.
  - The in-memory rate limiter resets on cold restart, but the **Single-Active-Run** and **Global Cooldown** checks query GitHub Actions directly, preserving durable protection across restarts.
- **Paid Tier (Starter / Standard):**
  - Always-on execution eliminates cold starts for evaluator presentations and videos.
  - Recommended if immediate page loads are needed during hackathon judging.

---

## 6. Verification & Health Monitoring

### Health Endpoint
```bash
curl -s https://<your-render-url>/api/health
# {"status":"ok","service":"cairn-app","version":"0.1.0","timestamp":"..."}
```

### Integration Status Endpoint
```bash
curl -s https://<your-render-url>/api/status
# {"service":"cairn-app","github_configured":true,"can_dispatch":true,"active_job":null,"cooldown_remaining_seconds":0,...}
```

### Local Testing of the Web Application
```bash
# Start local server with uvicorn
uvicorn cairn.webapp:app --host 127.0.0.1 --port 8000

# Open in browser:
# http://127.0.0.1:8000
```
