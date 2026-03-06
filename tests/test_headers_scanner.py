"""Tests for the HTTP headers scanner."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.scanners.headers_scanner import scan_headers


def _make_response(headers: dict, status_code: int = 200, url: str = "https://example.com"):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers
    resp.url = url
    return resp


async def _mock_scan(headers: dict, status_code: int = 200):
    """Patch httpx.AsyncClient to return a controlled response."""
    resp = _make_response(headers, status_code)

    with patch("app.scanners.headers_scanner.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=resp)
        mock_client_cls.return_value = mock_client

        return await scan_headers("example.com")


class TestHeadersScanner:
    def test_all_security_headers_present(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1; mode=block",
        }
        result = asyncio.get_event_loop().run_until_complete(_mock_scan(headers))
        assert result["missing_headers"] == []
        # No missing header findings
        header_findings = [f for f in result["findings"] if "missing security header" in f["title"].lower()]
        assert len(header_findings) == 0

    def test_missing_hsts(self):
        result = asyncio.get_event_loop().run_until_complete(_mock_scan({}))
        missing = [f for f in result["findings"] if "strict-transport-security" in f["title"].lower()]
        assert len(missing) >= 1
        assert missing[0]["severity"] == "high"

    def test_missing_csp(self):
        result = asyncio.get_event_loop().run_until_complete(_mock_scan({}))
        missing = [f for f in result["findings"] if "content-security-policy" in f["title"].lower()]
        assert len(missing) >= 1
        assert missing[0]["severity"] == "high"

    def test_server_header_disclosure(self):
        headers = {"server": "Apache/2.4.50 (Ubuntu)"}
        result = asyncio.get_event_loop().run_until_complete(_mock_scan(headers))
        disclosure = [f for f in result["findings"] if "server" in f["title"].lower() and "disclosure" in f["title"].lower()]
        assert len(disclosure) >= 1
        assert disclosure[0]["severity"] == "low"

    def test_x_powered_by_disclosure(self):
        headers = {"x-powered-by": "PHP/8.1.0"}
        result = asyncio.get_event_loop().run_until_complete(_mock_scan(headers))
        disclosure = [f for f in result["findings"] if "x-powered-by" in f["title"].lower()]
        assert len(disclosure) >= 1

    def test_hsts_max_age_zero(self):
        headers = {"strict-transport-security": "max-age=0"}
        result = asyncio.get_event_loop().run_until_complete(_mock_scan(headers))
        hsts_findings = [f for f in result["findings"] if "hsts" in f["title"].lower() and "zero" in f["title"].lower()]
        assert len(hsts_findings) >= 1
        assert hsts_findings[0]["severity"] == "high"

    def test_hsts_short_max_age(self):
        headers = {"strict-transport-security": "max-age=300"}
        result = asyncio.get_event_loop().run_until_complete(_mock_scan(headers))
        hsts_findings = [f for f in result["findings"] if "hsts" in f["title"].lower() and "short" in f["title"].lower()]
        assert len(hsts_findings) >= 1
        assert hsts_findings[0]["severity"] == "medium"

    def test_unreachable_site(self):
        with patch("app.scanners.headers_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("Connection failed"))
            mock_client_cls.return_value = mock_client

            result = asyncio.get_event_loop().run_until_complete(scan_headers("unreachable.invalid"))
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(critical) >= 1
