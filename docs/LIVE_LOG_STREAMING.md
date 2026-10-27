# CAIRN Live Log Streaming Configuration Guide

This document describes how to configure and operate the real-time command output streaming feature between **GitHub Actions** runners and the deployed **CAIRN Render Web Application**.

---

## 1. Architecture Overview

```text
GitHub Actions Runner (Ephemeral Ubuntu VM)
  │
  ├── Command: python scripts/stream_action_logs.py --step "<Step Name>" -- <command>
  │     ├── Prints full stdout & stderr to local GitHub Actions console
  │     ├── Redacts credentials ([REDACTED])
  │     └── Buffers lines into small batches (~0.5s interval)
  │           │
  │           ▼ HTTPS POST (Bearer Token)
Render Web Service (`cairn-app`)
  ├── POST /api/internal/logs
  │     ├── Constant-time token verification (CAIRN_LOG_INGEST_TOKEN)
  │     ├── Stream isolation (<run_id>-attempt-<attempt>)
  │     └── Bounded in-memory retention (pruning oldest/expired)
  │
  └── Evaluator Browser (site/index.html)
        ├── GET /api/workflows (Selects active/recent run)
        └── GET /api/workflows/{stream_id}/logs?after=<cursor> (Pulls new lines every ~1s)
```

### Key Security & Reliability Design Principles
1. **Runner Reliability First:** Log forwarding is purely supplementary. If Render is down, restarting, or the network drops, the benchmark command continues executing normally and its complete output remains in the GitHub Actions console. It will never fail an otherwise successful benchmark.
2. **Strict Credential Redaction:** Any token matching `ghp_*`, `github_pat_*`, `Bearer *`, or the values of `GITHUB_TOKEN` and `CAIRN_LOG_INGEST_TOKEN` are automatically scrubbed and replaced with `[REDACTED]` prior to transmission.
3. **No Private Runner Secrets in Frontend:** The browser never touches `CAIRN_LOG_INGEST_TOKEN` or `GITHUB_TOKEN`. Public users can only read sanitized log lines from the cursor endpoint.
4. **Stream & Attempt Isolation:** Each stream is tied to `<run-id>-attempt-<attempt>`. Re-runs or concurrent workflows never mix or overwrite each other's terminal buffers.

---

## 2. Configuration Setup

To enable live streaming from GitHub Actions to your deployed Render instance, complete the following setup steps:

### Step 1: Generate a Strong Shared Secret
Generate a cryptographically secure random token on your local machine:
```bash
openssl rand -hex 32
# Example output: e8c0b5f1903e1a2f6d89a714c35b02de9f018e7d23a4b6c810f3e7a9b0c2d4e6
```
*(Do not commit this token into Git).*

### Step 2: Configure Render Environment Variable
1. Open the [Render Dashboard](https://dashboard.render.com/).
2. Select your `cairn-app` web service.
3. Navigate to **Environment**.
4. Add the following environment variable:
   - **Key:** `CAIRN_LOG_INGEST_TOKEN`
   - **Value:** `<your-generated-random-token>`
5. Click **Save Changes**. Render will automatically redeploy the service with the new token.

### Step 3: Configure GitHub Actions Secret & Variable
1. In your GitHub repository (`https://github.com/Anurag-Singh2004/cairn`), navigate to **Settings** → **Secrets and variables** → **Actions**.

2. Under the **Secrets** tab, click **New repository secret**:
   - **Name:** `CAIRN_LOG_INGEST_TOKEN`
   - **Secret:** `<your-generated-random-token>` *(identical to the Render value)*
   - Click **Add secret**.

3. Under the **Variables** tab, click **New repository variable**:
   - **Name:** `CAIRN_LOG_INGEST_URL`
   - **Value:** `https://<your-render-service>.onrender.com/api/internal/logs`
     *(Replace `<your-render-service>` with your actual Render application domain).*
   - Click **Add variable**.

---

## 3. Verifying Live Streaming

1. Open your deployed CAIRN website URL (`https://<your-render-service>.onrender.com`).
2. Click **Run Live Demo**.
3. The UI will dispatch `cairn-demo.yml` on GitHub Actions and automatically select the stream in the console.
4. As the runner sets up Docker and begins `python -u -m cairn.cli demo`, watch the terminal window on the website update line by line in real time!
5. After the run finishes, the complete log output remains viewable, and the **Download Results (.zip)** and **View Report** links will appear.

---

## 4. In-Memory Retention & Limitations

- **Bounded Memory:** The Render backend maintains an in-memory buffer capped at:
  - Max 30 retained streams.
  - Max 5,000 lines per stream.
  - Max 2 MB per stream.
  - 2-hour inactivity expiration.
- **Backend Restarts:** Because the log buffer is maintained in-memory without an external database, restarting or re-deploying the Render application clears the active stream history.
- **Historical Workflows:** For completed runs that have expired from the in-memory buffer, users can click **View in GitHub ↗** to inspect the permanent logs in GitHub Actions.

---

## 5. Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| Console displays *"Remote streaming not configured"* in GitHub Actions | `CAIRN_LOG_INGEST_URL` or `CAIRN_LOG_INGEST_TOKEN` is unset. | Ensure both the repository secret and repository variable are defined in GitHub Settings. |
| Ingestion returns `HTTP 401 Unauthorized` | Token mismatch. | Verify `CAIRN_LOG_INGEST_TOKEN` in Render matches `CAIRN_LOG_INGEST_TOKEN` in GitHub Secrets exactly. |
| Ingestion returns `HTTP 503 Service Unavailable` | `CAIRN_LOG_INGEST_TOKEN` not configured on Render. | Set `CAIRN_LOG_INGEST_TOKEN` in Render Dashboard Environment. |
| Terminal shows *"Waiting for first log lines"* | Runner is still provisioning or building Docker containers. | Allow 15–30 seconds for the temporary GitHub Actions runner to allocate. Output will stream automatically as soon as the first instrumented step begins. |
