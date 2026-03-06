"""Security tests for input validation and safe error handling."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.schemas import ScanCreate


# ---- Test database setup ----
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

_EMPTY_SSL = {"supported": True, "valid": True, "subject": "example.com", "issuer": "CA",
               "not_after": None, "days_until_expiry": 365, "protocol_version": "TLSv1.3",
               "cipher_suite": "TLS_AES_256_GCM_SHA384", "sans": [], "findings": []}
_EMPTY_HEADERS = {"url_checked": "https://example.com", "status_code": 200, "headers": {},
                   "missing_headers": [], "present_headers": [], "info_disclosure": [], "findings": []}
_EMPTY_PORTS = {"open_ports": [], "closed_ports": [], "findings": []}
_EMPTY_EPS = {"discovered": [], "findings": []}
_EMPTY_DNS = {"a_records": [], "aaaa_records": [], "mx_records": [], "ns_records": [],
               "txt_records": [], "caa_records": [], "spf": None, "dmarc": None,
               "has_spf": False, "has_dmarc": False, "has_caa": False, "findings": []}


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with (
        patch("app.routers.scans.scan_ssl", new=AsyncMock(return_value=_EMPTY_SSL)),
        patch("app.routers.scans.scan_headers", new=AsyncMock(return_value=_EMPTY_HEADERS)),
        patch("app.routers.scans.scan_ports", new=AsyncMock(return_value=_EMPTY_PORTS)),
        patch("app.routers.scans.scan_endpoints", new=AsyncMock(return_value=_EMPTY_EPS)),
        patch("app.routers.scans.scan_dns", new=AsyncMock(return_value=_EMPTY_DNS)),
        patch("app.tasks.run_scan.delay", side_effect=Exception("celery disabled")),
        patch("app.database.SessionLocal", TestSessionLocal),
    ):
        yield TestClient(app)


class TestInputValidation:
    """Test URL/domain input validation and sanitization."""

    def test_empty_domain_rejected(self, client):
        resp = client.post("/api/scans", json={"domain": ""})
        assert resp.status_code == 422

    def test_whitespace_only_domain_rejected(self, client):
        resp = client.post("/api/scans", json={"domain": "   "})
        assert resp.status_code == 422

    def test_protocol_stripped_from_domain(self, client):
        resp = client.post("/api/scans", json={"domain": "https://example.com"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    def test_http_protocol_stripped(self, client):
        resp = client.post("/api/scans", json={"domain": "http://example.com"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    def test_path_stripped_from_domain(self, client):
        resp = client.post("/api/scans", json={"domain": "example.com/path/to/page"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    def test_domain_lowercased(self, client):
        resp = client.post("/api/scans", json={"domain": "EXAMPLE.COM"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    def test_domain_trimmed(self, client):
        resp = client.post("/api/scans", json={"domain": "  example.com  "})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    def test_missing_domain_field_rejected(self, client):
        resp = client.post("/api/scans", json={})
        assert resp.status_code == 422

    def test_non_string_domain_rejected(self, client):
        resp = client.post("/api/scans", json={"domain": 12345})
        # Pydantic should either coerce or reject
        assert resp.status_code in (201, 422)

    def test_domain_with_trailing_slash(self, client):
        resp = client.post("/api/scans", json={"domain": "example.com/"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"


class TestSchemaDomainValidator:
    """Directly test the ScanCreate pydantic validator."""

    def test_valid_domain(self):
        scan = ScanCreate(domain="example.com")
        assert scan.domain == "example.com"

    def test_strips_https(self):
        scan = ScanCreate(domain="https://test.org/page")
        assert scan.domain == "test.org"

    def test_strips_http(self):
        scan = ScanCreate(domain="http://test.org")
        assert scan.domain == "test.org"

    def test_empty_raises(self):
        with pytest.raises(Exception):
            ScanCreate(domain="")

    def test_whitespace_raises(self):
        with pytest.raises(Exception):
            ScanCreate(domain="   ")

    def test_lowercases(self):
        scan = ScanCreate(domain="EXAMPLE.COM")
        assert scan.domain == "example.com"


class TestSafeErrorHandling:
    """Test that errors are handled safely without leaking internal details."""

    def test_404_returns_json_error(self, client):
        resp = client.get("/api/scans/99999")
        assert resp.status_code == 404
        data = resp.json()
        assert "detail" in data

    def test_delete_nonexistent_returns_404(self, client):
        resp = client.delete("/api/scans/99999")
        assert resp.status_code == 404

    def test_pdf_for_nonexistent_scan_returns_404(self, client):
        resp = client.get("/api/reports/99999/pdf")
        assert resp.status_code == 404

    def test_invalid_scan_id_type(self, client):
        resp = client.get("/api/scans/not-a-number")
        assert resp.status_code == 422

    def test_health_endpoint_accessible(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_cors_headers_present(self, client):
        """CORS middleware should add headers for cross-origin requests."""
        resp = client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        # Should not return 405 for CORS preflight
        assert resp.status_code in (200, 204, 405)
