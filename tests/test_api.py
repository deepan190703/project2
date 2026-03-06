"""Tests for the FastAPI application endpoints."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models import ScanStatus


# ---- In-memory SQLite for testing (StaticPool shares one connection) ----
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Minimal scanner stubs so no real network calls are made during API tests
_EMPTY_SSL     = {"supported": True, "valid": True, "subject": "example.com", "issuer": "CA",
                   "not_after": None, "days_until_expiry": 365, "protocol_version": "TLSv1.3",
                   "cipher_suite": "TLS_AES_256_GCM_SHA384", "sans": [], "findings": []}
_EMPTY_HEADERS = {"url_checked": "https://example.com", "status_code": 200, "headers": {},
                   "missing_headers": [], "present_headers": [], "info_disclosure": [], "findings": []}
_EMPTY_PORTS   = {"open_ports": [], "closed_ports": [], "findings": []}
_EMPTY_EPS     = {"discovered": [], "findings": []}
_EMPTY_DNS     = {"a_records": [], "aaaa_records": [], "mx_records": [], "ns_records": [],
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
    """TestClient with all scanner network calls mocked out."""
    with (
        patch("app.routers.scans.scan_ssl",       new=AsyncMock(return_value=_EMPTY_SSL)),
        patch("app.routers.scans.scan_headers",   new=AsyncMock(return_value=_EMPTY_HEADERS)),
        patch("app.routers.scans.scan_ports",     new=AsyncMock(return_value=_EMPTY_PORTS)),
        patch("app.routers.scans.scan_endpoints", new=AsyncMock(return_value=_EMPTY_EPS)),
        patch("app.routers.scans.scan_dns",       new=AsyncMock(return_value=_EMPTY_DNS)),
        # Prevent Celery from being invoked (delay raises → fallback to BackgroundTasks)
        patch("app.tasks.run_scan.delay", side_effect=Exception("celery disabled")),
        # Background task uses SessionLocal directly; point it to the test DB
        patch("app.database.SessionLocal", TestSessionLocal),
    ):
        yield TestClient(app)


# ---- Health endpoint ----

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---- Create scan ----

def test_create_scan_valid_domain(client):
    resp = client.post("/api/scans", json={"domain": "example.com"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["status"] in ("pending", "running", "completed", "failed")
    assert "id" in data


def test_create_scan_strips_protocol(client):
    resp = client.post("/api/scans", json={"domain": "https://example.com/path"})
    assert resp.status_code == 201
    assert resp.json()["domain"] == "example.com"


def test_create_scan_empty_domain_rejected(client):
    resp = client.post("/api/scans", json={"domain": "   "})
    assert resp.status_code == 422


def test_create_scan_http_stripped(client):
    resp = client.post("/api/scans", json={"domain": "http://test.org"})
    assert resp.status_code == 201
    assert resp.json()["domain"] == "test.org"


# ---- List scans ----

def test_list_scans_empty(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["scans"] == []


def test_list_scans_returns_created_scan(client):
    client.post("/api/scans", json={"domain": "example.com"})
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["scans"][0]["domain"] == "example.com"


def test_list_scans_pagination(client):
    for i in range(5):
        client.post("/api/scans", json={"domain": f"test{i}.com"})
    resp = client.get("/api/scans?limit=2&skip=0")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["scans"]) == 2


# ---- Get single scan ----

def test_get_scan_not_found(client):
    resp = client.get("/api/scans/9999")
    assert resp.status_code == 404


def test_get_scan_returns_created_scan(client):
    create_resp = client.post("/api/scans", json={"domain": "check.io"})
    scan_id = create_resp.json()["id"]
    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id
    assert resp.json()["domain"] == "check.io"


# ---- Delete scan ----

def test_delete_scan(client):
    create_resp = client.post("/api/scans", json={"domain": "todelete.com"})
    scan_id = create_resp.json()["id"]
    del_resp = client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 204
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 404


def test_delete_nonexistent_scan(client):
    resp = client.delete("/api/scans/9999")
    assert resp.status_code == 404


# ---- PDF report endpoint ----

def test_pdf_report_not_found(client):
    resp = client.get("/api/reports/9999/pdf")
    assert resp.status_code == 404


def test_pdf_report_pending_scan_returns_400(client):
    create_resp = client.post("/api/scans", json={"domain": "pending.com"})
    scan_id = create_resp.json()["id"]

    # Force status to pending via DB
    db = TestSessionLocal()
    from app.models import ScanModel
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    scan.status = ScanStatus.PENDING
    db.commit()
    db.close()

    resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert resp.status_code == 400


def test_pdf_report_completed_scan_returns_pdf(client):
    """Insert a completed scan directly and verify the PDF is returned."""
    db = TestSessionLocal()
    from app.models import ScanModel
    from datetime import datetime, timezone

    scan = ScanModel(
        domain="complete.com",
        status=ScanStatus.COMPLETED,
        risk_score=30.0,
        risk_grade="C",
        findings=json.dumps([]),
        ssl_results=json.dumps({"supported": True, "valid": True, "findings": []}),
        headers_results=json.dumps({"present_headers": [], "missing_headers": [], "info_disclosure": [], "findings": []}),
        ports_results=json.dumps({"open_ports": [], "closed_ports": [], "findings": []}),
        endpoints_results=json.dumps({"discovered": [], "findings": []}),
        dns_results=json.dumps({"a_records": [], "findings": []}),
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
