"""Tests for CAIRN GitHub Actions live log streaming helper and backend ingestion API."""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

import cairn.webapp as webapp
from cairn.webapp import LOG_BUFFER, app


@pytest.fixture(autouse=True)
def clean_log_buffer():
    """Ensure in-memory log buffer and status cache are cleared before and after each test."""
    LOG_BUFFER.clear()
    webapp.GITHUB_STATUS_CACHE.clear()
    yield
    LOG_BUFFER.clear()
    webapp.GITHUB_STATUS_CACHE.clear()


# ============================================================================
# Backend Ingestion & Retrieval API Tests
# ============================================================================


@pytest.mark.asyncio
async def test_ingest_valid_authenticated_batch():
    """Verify authenticated batch is accepted and stored in log buffer."""
    test_token = "test_secret_token_1234567890"
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            payload = {
                "stream_id": "run101-attempt-1",
                "run_id": "run101",
                "attempt": "1",
                "workflow": "cairn-demo",
                "job": "benchmark",
                "step": "T0 Run",
                "lines": [
                    {"timestamp": "2026-10-28T00:00:01Z", "text": "Starting T0..."},
                    {"timestamp": "2026-10-28T00:00:02Z", "text": "T0 complete."},
                ],
            }
            resp = await client.post(
                "/api/internal/logs",
                json=payload,
                headers={"Authorization": f"Bearer {test_token}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["accepted"] == 2
            assert data["stream_id"] == "run101-attempt-1"

            # Query lines back
            lines_resp = await client.get("/api/workflows/run101-attempt-1/logs?after=0")
            assert lines_resp.status_code == 200
            lines_data = lines_resp.json()
            assert len(lines_data["lines"]) == 2
            assert lines_data["lines"][0]["sequence"] == 1
            assert lines_data["lines"][0]["text"] == "Starting T0..."
            assert lines_data["lines"][1]["sequence"] == 2
            assert lines_data["lines"][1]["text"] == "T0 complete."
            assert lines_data["next_cursor"] == 2


@pytest.mark.asyncio
async def test_ingest_unauthenticated_rejected():
    """Verify missing Authorization header is rejected with 401."""
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", "valid_token"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/internal/logs",
                json={"stream_id": "s1", "run_id": "1", "lines": [{"text": "hello"}]},
            )
            assert resp.status_code == 401
            assert "Unauthorized" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_incorrect_token_rejected():
    """Verify wrong token is rejected with 401."""
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", "correct_token_secret"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/internal/logs",
                json={"stream_id": "s1", "run_id": "1", "lines": [{"text": "hello"}]},
                headers={"Authorization": "Bearer wrong_token_value"},
            )
            assert resp.status_code == 401
            assert "Unauthorized" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_unconfigured_server_returns_503():
    """Verify ingestion returns 503 when CAIRN_LOG_INGEST_TOKEN is not configured."""
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", ""):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/internal/logs",
                json={"stream_id": "s1", "run_id": "1", "lines": [{"text": "hello"}]},
                headers={"Authorization": "Bearer some_token"},
            )
            assert resp.status_code == 503
            assert "not configured" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_ingest_oversized_batch_rejected():
    """Verify batches exceeding 500 lines are rejected with 400."""
    test_token = "test_secret_token"
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            large_lines = [{"text": f"line {i}"} for i in range(501)]
            resp = await client.post(
                "/api/internal/logs",
                json={"stream_id": "s1", "run_id": "1", "lines": large_lines},
                headers={"Authorization": f"Bearer {test_token}"},
            )
            assert resp.status_code == 400
            assert "500 lines" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_invalid_stream_id_format():
    """Verify invalid stream_id containing path traversal or illegal characters is rejected."""
    test_token = "test_secret_token"
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/internal/logs",
                json={"stream_id": "../../etc/passwd", "run_id": "1", "lines": [{"text": "hi"}]},
                headers={"Authorization": f"Bearer {test_token}"},
            )
            assert resp.status_code == 400
            assert "Invalid stream ID" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_stream_isolation_and_cursor_pagination():
    """Verify logs from distinct runs remain strictly isolated and cursor pagination works."""
    test_token = "test_secret_token"
    with patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {test_token}"}

            # Batch 1 for Stream A
            await client.post(
                "/api/internal/logs",
                json={
                    "stream_id": "stream-A",
                    "run_id": "100",
                    "lines": [{"text": f"A_line_{i}"} for i in range(1, 6)],
                },
                headers=headers,
            )

            # Batch for Stream B (concurrent)
            await client.post(
                "/api/internal/logs",
                json={
                    "stream_id": "stream-B",
                    "run_id": "200",
                    "lines": [{"text": "B_line_1"}, {"text": "B_line_2"}],
                },
                headers=headers,
            )

            # Check Stream A first page (after=0, limit=3)
            r1 = await client.get("/api/workflows/stream-A/logs?after=0&limit=3")
            assert r1.status_code == 200
            d1 = r1.json()
            assert len(d1["lines"]) == 3
            assert d1["lines"][0]["text"] == "A_line_1"
            assert d1["lines"][2]["text"] == "A_line_3"
            assert d1["next_cursor"] == 3
            assert d1["has_more"] is True

            # Check Stream A second page (after=3, limit=3)
            url_p2 = f"/api/workflows/stream-A/logs?after={d1['next_cursor']}&limit=3"
            r2 = await client.get(url_p2)
            assert r2.status_code == 200
            d2 = r2.json()
            assert len(d2["lines"]) == 2
            assert d2["lines"][0]["text"] == "A_line_4"
            assert d2["lines"][1]["text"] == "A_line_5"
            assert d2["next_cursor"] == 5
            assert d2["has_more"] is False

            # Check Stream B is completely isolated from A
            rb = await client.get("/api/workflows/stream-B/logs?after=0")
            assert rb.status_code == 200
            db = rb.json()
            assert len(db["lines"]) == 2
            assert db["lines"][0]["text"] == "B_line_1"
            assert db["lines"][1]["text"] == "B_line_2"
            assert not any("A_line" in line_item["text"] for line_item in db["lines"])


@pytest.mark.asyncio
async def test_buffer_retention_and_pruning():
    """Verify log stream enforces max line limits and prunes oldest entries."""
    test_token = "test_secret_token"
    with (
        patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token),
        patch.object(webapp, "MAX_LINES_PER_STREAM", 10),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {"Authorization": f"Bearer {test_token}"}

            # Ingest 15 lines into a stream capped at 10
            await client.post(
                "/api/internal/logs",
                json={
                    "stream_id": "capped-stream",
                    "run_id": "300",
                    "lines": [{"text": f"line_{i}"} for i in range(1, 16)],
                },
                headers=headers,
            )

            resp = await client.get("/api/workflows/capped-stream/logs?after=0&limit=50")
            assert resp.status_code == 200
            data = resp.json()
            # Buffer should have pruned oldest 5 lines, leaving exactly 10
            assert len(data["lines"]) == 10
            # Oldest remaining line should be line_6 (sequence 6)
            assert data["lines"][0]["text"] == "line_6"
            assert data["lines"][-1]["text"] == "line_15"


# ============================================================================
# Streaming Helper Tests (scripts/stream_action_logs.py)
# ============================================================================


def test_helper_captures_stdout_and_stderr(tmp_path):
    """Verify helper captures both stdout and stderr, printing them to console."""
    cmd = [
        sys.executable,
        "scripts/stream_action_logs.py",
        "--step",
        "Test Output",
        "--",
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('stdout line\\n'); sys.stderr.write('stderr line\\n')",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert "stdout line" in res.stdout
    assert "stderr line" in res.stdout


def test_helper_preserves_exit_code():
    """Verify helper preserves exact child return code for nonzero exits."""
    cmd = [
        sys.executable,
        "scripts/stream_action_logs.py",
        "--step",
        "Test Exit Code",
        "--",
        sys.executable,
        "-c",
        "import sys; sys.exit(73)",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 73


def test_helper_resilience_when_backend_unavailable():
    """Verify helper does not fail a successful command when backend port is unreachable."""
    cmd = [
        sys.executable,
        "scripts/stream_action_logs.py",
        "--step",
        "Test Resilience",
        "--url",
        "http://127.0.0.1:59999/api/internal/logs",  # unreachable port
        "--token",
        "test_token",
        "--",
        sys.executable,
        "-c",
        "print('command executed despite network failure')",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    # The actual child command succeeded, so exit code MUST be 0!
    assert res.returncode == 0
    assert "command executed despite network failure" in res.stdout


def test_helper_redacts_secrets_in_logs():
    """Verify helper redacts secret tokens and known secrets before transmission."""
    import importlib.util

    script_path = Path(__file__).resolve().parents[2] / "scripts" / "stream_action_logs.py"
    spec = importlib.util.spec_from_file_location("stream_action_logs", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    redact_line = mod.redact_line

    known = ["super_secret_api_key_xyz", "my_github_token_123"]
    raw_text = (
        "Config token: super_secret_api_key_xyz, "
        "User token: ghp_1234567890abcdef1234567890abcdef, "
        "Env token: my_github_token_123"
    )
    redacted = redact_line(raw_text, known)

    assert "super_secret_api_key_xyz" not in redacted
    assert "ghp_1234567890abcdef1234567890abcdef" not in redacted
    assert "my_github_token_123" not in redacted
    assert "[REDACTED]" in redacted


# ============================================================================
# Incremental Streaming Test with Live Subprocess
# ============================================================================


class MockLogServer(http.server.HTTPServer):
    """Simple test HTTP server that records received log batches in memory."""

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.received_batches: list[dict[str, Any]] = []


class MockLogHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len)
        try:
            batch = json.loads(post_data.decode("utf-8"))
            self.server.received_batches.append(batch)
        except Exception:
            pass

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        # Silence HTTP server access logs in pytest output
        pass


def test_incremental_streaming_delivery_during_command_execution():
    """Demonstrate that log batches arrive incrementally while child command is running."""
    # Start ephemeral local mock ingestion server on random port
    server = MockLogServer(("127.0.0.1", 0), MockLogHandler)
    server_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    ingest_url = f"http://127.0.0.1:{server_port}/api/internal/logs"

    # Command that prints 3 lines with 0.3s sleep in between
    slow_script = (
        "import sys, time\n"
        "sys.stdout.write('Line 1: starting benchmark\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.4)\n"
        "sys.stdout.write('Line 2: running probe L1\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(0.4)\n"
        "sys.stdout.write('Line 3: finished\\n')\n"
        "sys.stdout.flush()\n"
    )

    helper_cmd = [
        sys.executable,
        "scripts/stream_action_logs.py",
        "--step",
        "Incremental Test",
        "--url",
        ingest_url,
        "--token",
        "mock_token",
        "--batch-interval",
        "0.2",
        "--run-id",
        "inc-test-run",
        "--attempt",
        "1",
        "--",
        sys.executable,
        "-u",
        "-c",
        slow_script,
    ]

    # Start child process
    proc = subprocess.Popen(helper_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Poll during execution (~0.35s: Line 1 delivered while running)
    time.sleep(0.35)
    batches_during_run = len(server.received_batches)

    # Wait for process to fully complete
    stdout, _stderr = proc.communicate(timeout=6.0)
    server.shutdown()

    # 1. Exit code preserved
    assert proc.returncode == 0
    # 2. Output displayed in stdout
    assert "Line 1: starting benchmark" in stdout
    assert "Line 2: running probe L1" in stdout
    assert "Line 3: finished" in stdout
    # 3. Batches were delivered incrementally while command was still executing!
    assert batches_during_run >= 1, "At least one batch must arrive before process terminates!"
    # 4. Total delivered lines across all batches
    all_lines = []
    for b in server.received_batches:
        all_lines.extend(b.get("lines", []))

    assert len(all_lines) == 3
    assert all_lines[0]["text"] == "Line 1: starting benchmark"
    assert all_lines[1]["text"] == "Line 2: running probe L1"
    assert all_lines[2]["text"] == "Line 3: finished"


# ============================================================================
# Status Synchronization & Progress Panel Tests
# ============================================================================


@pytest.mark.asyncio
async def test_workflow_status_running_when_github_in_progress():
    """Verify in-progress GitHub workflow maps to RUNNING with active step."""
    mock_run = {
        "id": 901,
        "run_attempt": 1,
        "name": "CAIRN Demo",
        "status": "in_progress",
        "conclusion": None,
        "html_url": "https://github.com/Anurag-Singh2004/cairn/actions/runs/901",
        "updated_at": "2026-10-28T02:00:00Z",
    }
    mock_jobs = {
        "jobs": [
            {
                "id": 501,
                "name": "Execute CAIRN Demo Benchmark",
                "status": "in_progress",
                "conclusion": None,
                "steps": [
                    {"name": "Set up Python", "status": "completed", "conclusion": "success"},
                    {
                        "name": "Execute end-to-end benchmark demo",
                        "status": "in_progress",
                        "conclusion": None,
                    },
                    {"name": "Package artifacts", "status": "queued", "conclusion": None},
                ],
            }
        ]
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if endpoint == "actions/runs/901":
            return httpx.Response(200, json=mock_run)
        if endpoint == "actions/runs/901/jobs":
            return httpx.Response(200, json=mock_jobs)
        return httpx.Response(404)

    with (
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/workflows/901-attempt-1/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["display_status"] == "IN_PROGRESS"
            assert data["current_job"] == "Execute CAIRN Demo Benchmark"
            assert data["current_step"] == "Execute end-to-end benchmark demo"
            assert data["steps_completed"] == 1
            assert data["steps_total"] == 3
            assert data["progress_pct"] == 33
            assert data["github_available"] is True
            assert data["is_stale"] is False


@pytest.mark.asyncio
async def test_workflow_status_success_when_github_completed_success():
    """Verify completed GitHub workflow maps to SUCCESS with final step."""
    mock_run = {
        "id": 902,
        "run_attempt": 1,
        "name": "CAIRN Demo",
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/Anurag-Singh2004/cairn/actions/runs/902",
        "updated_at": "2026-10-28T02:05:00Z",
    }
    mock_jobs = {
        "jobs": [
            {
                "id": 502,
                "name": "Execute CAIRN Demo Benchmark",
                "status": "completed",
                "conclusion": "success",
                "steps": [
                    {"name": "Set up Python", "status": "completed", "conclusion": "success"},
                    {
                        "name": "Execute end-to-end benchmark demo",
                        "status": "completed",
                        "conclusion": "success",
                    },
                    {"name": "Package artifacts", "status": "completed", "conclusion": "success"},
                ],
            }
        ]
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if endpoint == "actions/runs/902":
            return httpx.Response(200, json=mock_run)
        if endpoint == "actions/runs/902/jobs":
            return httpx.Response(200, json=mock_jobs)
        return httpx.Response(404)

    with (
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/workflows/902-attempt-1/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["display_status"] == "SUCCESS"
            assert data["current_step"] == "Package artifacts"
            assert data["steps_completed"] == 3
            assert data["steps_total"] == 3
            assert data["progress_pct"] == 100


@pytest.mark.asyncio
async def test_workflow_status_failed_when_github_failed():
    """Verify failed GitHub workflow maps to FAILED."""
    mock_run = {
        "id": 903,
        "run_attempt": 1,
        "name": "CI Tests",
        "status": "completed",
        "conclusion": "failure",
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if endpoint == "actions/runs/903":
            return httpx.Response(200, json=mock_run)
        if endpoint == "actions/runs/903/jobs":
            return httpx.Response(200, json={"jobs": []})
        return httpx.Response(404)

    with (
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/workflows/903-attempt-1/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["display_status"] == "FAILED"


@pytest.mark.asyncio
async def test_workflow_status_cancelled_when_github_cancelled():
    """Verify cancelled GitHub workflow maps to CANCELLED."""
    mock_run = {
        "id": 904,
        "run_attempt": 1,
        "name": "CI Tests",
        "status": "completed",
        "conclusion": "cancelled",
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if endpoint == "actions/runs/904":
            return httpx.Response(200, json=mock_run)
        if endpoint == "actions/runs/904/jobs":
            return httpx.Response(200, json={"jobs": []})
        return httpx.Response(404)

    with (
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/workflows/904-attempt-1/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["display_status"] == "CANCELLED"


@pytest.mark.asyncio
async def test_presence_of_buffered_logs_does_not_force_in_progress():
    """Verify having buffered logs in memory does not force workflow status to in_progress."""
    # Add buffered logs for stream 905-attempt-1
    test_token = "valid_tok"
    payload = {
        "stream_id": "905-attempt-1",
        "run_id": "905",
        "attempt": "1",
        "workflow": "CAIRN Demo",
        "job": "demo",
        "step": "Package Artifacts",
        "lines": [{"text": "artifact line 1"}],
    }

    mock_run = {
        "id": 905,
        "run_attempt": 1,
        "name": "CAIRN Demo",
        "status": "completed",
        "conclusion": "success",
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if endpoint == "actions/runs/905":
            return httpx.Response(200, json=mock_run)
        if endpoint == "actions/runs/905/jobs":
            return httpx.Response(200, json={"jobs": []})
        return httpx.Response(404)

    with (
        patch.object(webapp, "CAIRN_LOG_INGEST_TOKEN", test_token),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # 1. Post batch into buffer
            post_resp = await client.post(
                "/api/internal/logs",
                json=payload,
                headers={"Authorization": f"Bearer {test_token}"},
            )
            assert post_resp.status_code == 200

            # 2. Query logs
            logs_resp = await client.get("/api/workflows/905-attempt-1/logs?after=0")
            assert logs_resp.status_code == 200
            logs_data = logs_resp.json()
            # Must reflect actual GitHub completion, NOT hardcoded in_progress!
            assert logs_data["workflow_status"] == "success"

            # 3. Query status endpoint
            status_resp = await client.get("/api/workflows/905-attempt-1/status")
            assert status_resp.status_code == 200
            assert status_resp.json()["display_status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_unknown_status_when_github_unavailable():
    """Verify unknown status reported honestly when GitHub API is unconfigured."""
    with patch.object(webapp, "is_github_configured", return_value=False):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/workflows/999-attempt-1/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["display_status"] == "UNKNOWN"
            assert data["github_available"] is False


@pytest.mark.asyncio
async def test_stale_cache_returned_when_github_request_errors():
    """Verify cached status is returned with is_stale=True if GitHub API fails subsequently."""
    mock_run = {
        "id": 906,
        "run_attempt": 1,
        "name": "CAIRN Demo",
        "status": "in_progress",
        "conclusion": None,
    }

    call_count = 0

    async def fake_gh_request(method, endpoint, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            if endpoint == "actions/runs/906":
                return httpx.Response(200, json=mock_run)
            return httpx.Response(200, json={"jobs": []})
        raise httpx.RequestError("GitHub API timeout")

    with (
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # First call succeeds and caches
            r1 = await client.get("/api/workflows/906-attempt-1/status")
            assert r1.status_code == 200
            assert r1.json()["is_stale"] is False

            # Force cache expiration
            webapp.GITHUB_STATUS_CACHE._cache["906:1"]["expires_at"] = time.time() - 1

            # Second call encounters network error, must return stale cached entry
            r2 = await client.get("/api/workflows/906-attempt-1/status")
            assert r2.status_code == 200
            d2 = r2.json()
            assert d2["is_stale"] is True
            assert d2["display_status"] == "IN_PROGRESS"
