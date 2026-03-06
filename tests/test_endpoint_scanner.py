"""Tests for the endpoint discovery scanner."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.scanners.endpoint_scanner import scan_endpoints, SENSITIVE_PATHS


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_response(status_code: int):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    return resp


async def _mock_scan(path_status_map: dict):
    """
    Patch httpx.AsyncClient to return specific status codes per path.

    path_status_map: { "/admin": 200, "/.env": 403, ... }
    Paths not in the map return 404.
    """

    async def fake_get(url, **kwargs):
        for path, code in path_status_map.items():
            if url.endswith(path):
                return _make_response(code)
        return _make_response(404)

    with patch("app.scanners.endpoint_scanner.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_client_cls.return_value = mock_client

        return await scan_endpoints("example.com")


class TestEndpointScanner:
    def test_no_endpoints_found(self):
        result = _run(_mock_scan({}))
        assert result["discovered"] == []
        assert result["findings"] == []

    def test_admin_panel_discovered(self):
        result = _run(_mock_scan({"/admin": 200}))
        discovered_paths = [e["path"] for e in result["discovered"]]
        assert "/admin" in discovered_paths

    def test_admin_panel_generates_finding(self):
        result = _run(_mock_scan({"/admin": 200}))
        admin_findings = [
            f for f in result["findings"]
            if "/admin" in f["title"]
        ]
        assert len(admin_findings) >= 1
        assert admin_findings[0]["severity"] == "high"
        assert admin_findings[0]["category"] == "endpoints"

    def test_env_file_exposed(self):
        result = _run(_mock_scan({"/.env": 200}))
        env_findings = [
            f for f in result["findings"]
            if ".env" in f["title"]
        ]
        assert len(env_findings) >= 1
        assert env_findings[0]["severity"] == "critical"

    def test_git_config_exposed(self):
        result = _run(_mock_scan({"/.git/config": 200}))
        git_findings = [
            f for f in result["findings"]
            if ".git" in f["title"]
        ]
        assert len(git_findings) >= 1
        assert git_findings[0]["severity"] == "critical"

    def test_phpmyadmin_exposed(self):
        result = _run(_mock_scan({"/phpmyadmin/": 200}))
        pma_findings = [
            f for f in result["findings"]
            if "phpmyadmin" in f["title"].lower()
        ]
        assert len(pma_findings) >= 1
        assert pma_findings[0]["severity"] == "critical"

    def test_forbidden_resource_still_discovered(self):
        """A 403 response indicates the resource exists but access is restricted."""
        result = _run(_mock_scan({"/admin": 403}))
        discovered_paths = [e["path"] for e in result["discovered"]]
        assert "/admin" in discovered_paths
        admin_entry = [e for e in result["discovered"] if e["path"] == "/admin"][0]
        assert admin_entry["status_code"] == 403

    def test_403_finding_includes_access_restricted_note(self):
        result = _run(_mock_scan({"/admin": 403}))
        admin_findings = [f for f in result["findings"] if "/admin" in f["title"]]
        assert len(admin_findings) >= 1
        assert "restricted" in admin_findings[0]["description"].lower()

    def test_info_level_endpoints_no_findings(self):
        """Info-level endpoints (robots.txt, sitemap.xml) should be discovered but not generate findings."""
        result = _run(_mock_scan({"/robots.txt": 200, "/sitemap.xml": 200}))
        discovered_paths = [e["path"] for e in result["discovered"]]
        assert "/robots.txt" in discovered_paths
        # Info-level findings should not be generated (severity check in code: only critical/high/medium)
        info_findings = [f for f in result["findings"] if f["severity"] == "info"]
        assert len(info_findings) == 0

    def test_discovered_entry_has_required_fields(self):
        result = _run(_mock_scan({"/admin": 200}))
        assert len(result["discovered"]) >= 1
        entry = result["discovered"][0]
        assert "path" in entry
        assert "description" in entry
        assert "status_code" in entry
        assert "severity" in entry

    def test_finding_has_required_fields(self):
        result = _run(_mock_scan({"/admin": 200}))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding
        assert "category" in finding
        assert "recommendation" in finding

    def test_multiple_sensitive_endpoints(self):
        result = _run(_mock_scan({
            "/.env": 200,
            "/.git/config": 200,
            "/admin": 200,
            "/backup.sql": 200,
        }))
        discovered_paths = {e["path"] for e in result["discovered"]}
        assert "/.env" in discovered_paths
        assert "/.git/config" in discovered_paths
        assert "/admin" in discovered_paths
        assert "/backup.sql" in discovered_paths
        assert len(result["findings"]) >= 4

    def test_connection_error_handled_gracefully(self):
        """If all requests fail, no endpoints are discovered."""

        async def failing_get(url, **kwargs):
            raise Exception("Connection failed")

        with patch("app.scanners.endpoint_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=failing_get)
            mock_client_cls.return_value = mock_client

            result = _run(scan_endpoints("unreachable.invalid"))
        assert result["discovered"] == []
        assert result["findings"] == []
