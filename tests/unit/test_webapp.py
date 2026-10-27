"""Unit tests for CAIRN web application, API routes, and GitHub Actions integration."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import cairn.webapp as webapp
from cairn.webapp import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
async def test_api_health():
    """Verify health endpoint returns ok and valid timestamp."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "cairn-app"
        assert "timestamp" in data


@pytest.mark.asyncio
async def test_api_status_unconfigured():
    """Verify status endpoint safely handles missing GITHUB_TOKEN without secret leaks."""
    with patch.object(webapp, "GITHUB_TOKEN", ""):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["github_configured"] is False
            assert data["can_dispatch"] is False
            assert "GITHUB_TOKEN" not in str(data)
            assert data["repository"] == "Anurag-Singh2004/cairn"


@pytest.mark.asyncio
async def test_serve_index_html():
    """Verify root endpoint serves the interactive evaluator UI."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Live Benchmark Execution Console" in resp.text
        assert "WORKFLOW STATUS" in resp.text
        assert "Run CAIRN security benchmarks." in resp.text
        assert "Run" in resp.text


@pytest.mark.asyncio
async def test_api_latest_fallback_to_historical():
    """Verify /api/latest returns structured metrics from docs/RESULTS.md."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/latest")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_historical"] is True
        assert "Historical Reference Run" in data["source"]
        assert "probes" in data
        assert "l1" in data["probes"]
        assert "l3" in data["probes"]
        assert "l4" in data["probes"]
        assert "c3" in data["probes"]
        assert "runs" in data
        assert "t0" in data["runs"]
        assert "t1" in data["runs"]


@pytest.mark.asyncio
async def test_create_job_unconfigured_fails_503():
    """Verify job dispatch returns 503 when GITHUB_TOKEN is not configured."""
    with patch.object(webapp, "GITHUB_TOKEN", ""):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/jobs")
            assert resp.status_code == 503
            assert "GITHUB_TOKEN" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_client_rate_limiting():
    """Verify sliding-window rate limiter blocks excessive requests."""
    webapp.CLIENT_REQUEST_HISTORY.clear()
    client_ip = "192.0.2.1"

    for _ in range(5):
        assert webapp.check_client_rate_limit(client_ip, limit=5, window_seconds=60) is True

    # 6th request within window must be rejected
    assert webapp.check_client_rate_limit(client_ip, limit=5, window_seconds=60) is False


@pytest.mark.asyncio
async def test_create_job_active_run_conflict():
    """Verify job dispatch returns 409 Conflict when a benchmark is already running."""
    with (
        patch.object(webapp, "GITHUB_TOKEN", "ghp_fake_test_token_123456"),
        patch.object(
            webapp,
            "check_active_run_and_cooldown",
            AsyncMock(return_value=({"status": "in_progress", "id": 123}, 0)),
        ),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/jobs")
            assert resp.status_code == 409
            assert "already in progress" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_job_cooldown_active():
    """Verify job dispatch returns 429 when cooldown is active."""
    with (
        patch.object(webapp, "GITHUB_TOKEN", "ghp_fake_test_token_123456"),
        patch.object(webapp, "check_active_run_and_cooldown", AsyncMock(return_value=(None, 450))),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/jobs")
            assert resp.status_code == 429
            assert "cooldown active" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_job_success():
    """Verify successful dispatch triggers GitHub API and records job."""
    fake_resp = httpx.Response(204, request=httpx.Request("POST", "http://fake"))

    with (
        patch.object(webapp, "GITHUB_TOKEN", "ghp_fake_test_token_123456"),
        patch.object(webapp, "check_active_run_and_cooldown", AsyncMock(return_value=(None, 0))),
        patch.object(webapp, "github_api_request", AsyncMock(return_value=fake_resp)),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/jobs")
            assert resp.status_code == 202
            data = resp.json()
            assert data["status"] == "queued"
            assert "job_id" in data
            assert len(data["job_id"]) > 4


@pytest.mark.asyncio
async def test_get_job_status_validation():
    """Verify job status endpoint validates job ID format."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Invalid format / path traversal attempt
        resp = await client.get("/api/jobs/../../etc/passwd")
        assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_get_job_status_correlated():
    """Verify job status query correlates with GitHub workflow runs."""
    fake_runs = [
        {
            "id": 998877,
            "name": "cairn-demo-abc12345",
            "status": "in_progress",
            "conclusion": None,
            "html_url": "https://github.com/Anurag-Singh2004/cairn/actions/runs/998877",
            "created_at": "2026-10-26T17:20:00Z",
            "updated_at": "2026-10-26T17:21:00Z",
        }
    ]

    with (
        patch.object(webapp, "GITHUB_TOKEN", "ghp_fake_test_token_123456"),
        patch.object(webapp, "get_github_workflow_runs", AsyncMock(return_value=fake_runs)),
        patch.object(
            webapp,
            "github_api_request",
            AsyncMock(
                return_value=httpx.Response(
                    200,
                    json={
                        "jobs": [
                            {
                                "steps": [
                                    {"name": "Execute make demo", "status": "in_progress"},
                                ]
                            }
                        ]
                    },
                    request=httpx.Request("GET", "http://fake"),
                )
            ),
        ),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/jobs/abc12345")
            assert resp.status_code == 200
            data = resp.json()
            assert data["job_id"] == "abc12345"
            assert data["github_run_id"] == 998877
            assert data["status"] == "in_progress"
            assert "Execute make demo" in data["stage"]


@pytest.mark.asyncio
async def test_artifact_zip_allowlisting_and_safety(tmp_path: Path):
    """Verify artifact download streams zip containing allowlisted files and no secrets."""
    job_id = "testjob123"
    job_dir = tmp_path / job_id
    job_dir.mkdir(parents=True)

    # Allowlisted files
    (job_dir / "RESULTS.md").write_text("# Test Results", encoding="utf-8")
    (job_dir / "summary.json").write_text('{"request_id": "testjob123"}', encoding="utf-8")
    tier_dir = job_dir / "r_demo_t1_test"
    tier_dir.mkdir()
    (tier_dir / "results.json").write_text('{"tier": "t1"}', encoding="utf-8")

    # Forbidden files (must NEVER be included in output zip)
    (job_dir / "ref_ed25519.key").write_text("SUPER_SECRET_KEY", encoding="utf-8")
    (job_dir / "evidence.db").write_text("SQLITE_DATA", encoding="utf-8")
    (job_dir / ".env").write_text("GITHUB_TOKEN=secret", encoding="utf-8")

    with patch.object(webapp, "CACHE_DIR", tmp_path):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/artifacts.zip")
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/zip"

            # Inspect zip contents
            zf = zipfile.ZipFile(io.BytesIO(resp.content))
            namelist = zf.namelist()

            # Allowlisted files must be present
            assert "RESULTS.md" in namelist
            assert "summary.json" in namelist
            assert "r_demo_t1_test/results.json" in namelist

            # Forbidden files must be excluded
            for name in namelist:
                assert not name.endswith(".key")
                assert not name.endswith(".db")
                assert not name.endswith(".env")
                assert "SUPER_SECRET" not in zf.read(name).decode("utf-8", errors="ignore")


@pytest.mark.asyncio
async def test_parse_job_artifacts(tmp_path: Path):
    """Verify parse_job_artifacts correctly enriches live results from disk."""
    job_dir = tmp_path / "job_mock"
    job_dir.mkdir()
    (job_dir / "RESULTS.md").write_text(
        "| **Hardened Isolation Tier** | `r_live_t1` | T1 | `SIMULATED` | 12 | `root123` |\n",
        encoding="utf-8",
    )
    (job_dir / "summary.json").write_text(
        '{"github_run_id": 1234, "tiers": {"t1": "r_live_t1"}}',
        encoding="utf-8",
    )
    t1_dir = job_dir / "r_live_t1"
    t1_dir.mkdir()
    (t1_dir / "results.json").write_text(
        '{"findings_total": 12, "tier": "t1"}',
        encoding="utf-8",
    )

    parsed = webapp.parse_job_artifacts(job_dir, "job_mock")
    assert parsed["is_historical"] is False
    assert parsed["source"] == "Live GitHub Actions Run (cairn-demo-job_mock)"
    assert parsed["github_run_id"] == 1234
    assert parsed["t1_detailed"]["findings_total"] == 12


# ============================================================================
# Report HTML Endpoint Regression Tests
# ============================================================================


@pytest.mark.asyncio
async def test_view_report_html_invalid_job_id():
    """Verify invalid job ID format returns HTTP 400."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/jobs/bad..id/report.html")
        assert resp.status_code == 400
        assert "Invalid job ID format" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_view_report_html_present_in_cache(tmp_path: Path):
    """Verify report already present in local cache is returned immediately."""
    job_id = "cached_job_123"
    job_dir = tmp_path / job_id
    t1_dir = job_dir / "r_demo_t1_abc"
    t1_dir.mkdir(parents=True)
    report_content = "<html><body><h1>CAIRN Benchmark Report</h1></body></html>"
    (t1_dir / "report.html").write_text(report_content, encoding="utf-8")

    with patch.object(webapp, "CACHE_DIR", tmp_path):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "CAIRN Benchmark Report" in resp.text


@pytest.mark.asyncio
async def test_view_report_html_retrieved_from_github_when_cache_absent(tmp_path: Path):
    """Verify report is downloaded and served when local cache is absent."""
    job_id = "remote_job_456"
    run_id = 998877

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }

    zip_buf = io.BytesIO()
    report_html_text = "<html><body><h1>Remote Downloaded Report</h1></body></html>"
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("summary.json", '{"tiers": {"t1": "r_demo_t1_remote"}}')
        zf.writestr("r_demo_t1_remote/report.html", report_html_text)
    zip_bytes = zip_buf.getvalue()

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        if endpoint == f"actions/runs/{run_id}/artifacts":
            return httpx.Response(
                200,
                json={"artifacts": [{"id": 1122, "name": f"cairn-artifacts-{job_id}"}]},
            )
        if endpoint == "actions/artifacts/1122/zip":
            return httpx.Response(200, content=zip_bytes)
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "Remote Downloaded Report" in resp.text


@pytest.mark.asyncio
async def test_view_report_html_cache_exists_but_report_missing(tmp_path: Path):
    """Verify partial cache without report.html forces artifact download from GitHub."""
    job_id = "partial_cache_job"
    run_id = 887766

    job_dir = tmp_path / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "summary.json").write_text('{"partial": true}', encoding="utf-8")

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("summary.json", '{"tiers": {}}')
        zf.writestr("r_demo_t1/report.html", "<html><body>Recovered Partial Cache</body></html>")
    zip_bytes = zip_buf.getvalue()

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        if endpoint == f"actions/runs/{run_id}/artifacts":
            return httpx.Response(
                200,
                json={"artifacts": [{"id": 3344, "name": f"cairn-artifacts-{job_id}"}]},
            )
        if endpoint == "actions/artifacts/3344/zip":
            return httpx.Response(200, content=zip_bytes)
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 200
            assert "Recovered Partial Cache" in resp.text


@pytest.mark.asyncio
async def test_view_report_html_workflow_still_running(tmp_path: Path):
    """Verify HTTP 409 is returned when workflow is still in progress."""
    job_id = "running_job_777"
    run_id = 777000

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "in_progress",
        "conclusion": None,
        "run_attempt": 1,
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 409
            assert "still in_progress" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_view_report_html_workflow_failed_or_cancelled(tmp_path: Path):
    """Verify HTTP 400 is returned when workflow failed or was cancelled."""
    job_id = "failed_job_888"
    run_id = 888000

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "completed",
        "conclusion": "failure",
        "run_attempt": 1,
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 400
            assert "conclusion: 'failure'" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_view_report_html_successful_workflow_with_no_report_in_artifact(tmp_path: Path):
    """Verify HTTP 404 when artifact downloads successfully but report.html is missing."""
    job_id = "no_report_job"
    run_id = 554433

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("summary.json", '{"tiers": {}}')
        zf.writestr("RESULTS.md", "# Results")
    zip_bytes = zip_buf.getvalue()

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        if endpoint == f"actions/runs/{run_id}/artifacts":
            return httpx.Response(
                200,
                json={"artifacts": [{"id": 9900, "name": f"cairn-artifacts-{job_id}"}]},
            )
        if endpoint == "actions/artifacts/9900/zip":
            return httpx.Response(200, content=zip_bytes)
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 404
            assert (
                "Report HTML was not found in the completed workflow artifact"
                in resp.json()["detail"]
            )


@pytest.mark.asyncio
async def test_view_report_html_github_api_download_failure(tmp_path: Path):
    """Verify HTTP 502 when GitHub API artifacts request fails."""
    job_id = "dl_fail_job"
    run_id = 665544

    mock_run = {
        "id": run_id,
        "name": f"cairn-demo-{job_id}",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }

    async def fake_gh_request(method, endpoint, **kwargs):
        if "actions/workflows" in endpoint and "runs" in endpoint:
            return httpx.Response(200, json={"workflow_runs": [mock_run]})
        if endpoint == f"actions/runs/{run_id}/artifacts":
            return httpx.Response(500, text="Internal GitHub Error")
        return httpx.Response(404)

    with (
        patch.object(webapp, "CACHE_DIR", tmp_path),
        patch.object(webapp, "is_github_configured", return_value=True),
        patch.object(webapp, "github_api_request", side_effect=fake_gh_request),
    ):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(f"/api/jobs/{job_id}/report.html")
            assert resp.status_code == 502
            assert "Failed to retrieve artifact archive" in resp.json()["detail"]
