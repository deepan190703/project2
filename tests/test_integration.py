"""Integration tests for module interaction and end-to-end scan workflow."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models import ScanModel, ScanStatus
from app.scanners.scoring import aggregate_findings, compute_risk_score
from app.pdf_generator import generate_pdf_report


# ---- Test database setup ----
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


# Realistic scanner results for integration testing
MOCK_SSL = {
    "supported": True,
    "valid": True,
    "subject": "example.com",
    "issuer": "Let's Encrypt",
    "not_after": "2025-12-31T00:00:00+00:00",
    "days_until_expiry": 200,
    "protocol_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "sans": ["DNS:example.com", "DNS:www.example.com"],
    "findings": [],
}

MOCK_HEADERS = {
    "url_checked": "https://example.com",
    "status_code": 200,
    "headers": {},
    "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy"],
    "present_headers": ["X-Frame-Options"],
    "info_disclosure": [{"header": "Server", "value": "nginx/1.18"}],
    "findings": [
        {
            "title": "Missing Security Header: Strict-Transport-Security",
            "description": "HSTS header is missing.",
            "severity": "high",
            "category": "headers",
            "recommendation": "Add HSTS header.",
        },
        {
            "title": "Missing Security Header: Content-Security-Policy",
            "description": "CSP header is missing.",
            "severity": "high",
            "category": "headers",
            "recommendation": "Add CSP header.",
        },
        {
            "title": "Information Disclosure: Server",
            "description": "Server header reveals nginx/1.18.",
            "severity": "low",
            "category": "headers",
            "recommendation": "Remove Server header.",
        },
    ],
}

MOCK_PORTS = {
    "open_ports": [
        {"port": 80, "service": "HTTP", "severity": "info"},
        {"port": 443, "service": "HTTPS", "severity": "info"},
        {"port": 22, "service": "SSH", "severity": "info"},
    ],
    "closed_ports": [],
    "findings": [
        {
            "title": "HTTP (Port 80) Open – Redirect to HTTPS Recommended",
            "description": "Port 80 is open.",
            "severity": "low",
            "category": "ports",
            "recommendation": "Redirect HTTP to HTTPS.",
        },
    ],
}

MOCK_ENDPOINTS = {
    "discovered": [
        {"path": "/robots.txt", "description": "Robots.txt file", "status_code": 200, "severity": "info"},
    ],
    "findings": [],
}

MOCK_DNS = {
    "a_records": ["93.184.216.34"],
    "aaaa_records": [],
    "mx_records": ["10 mail.example.com."],
    "ns_records": ["ns1.example.com."],
    "txt_records": ['"v=spf1 include:_spf.google.com ~all"'],
    "caa_records": ['0 issue "letsencrypt.org"'],
    "spf": '"v=spf1 include:_spf.google.com ~all"',
    "dmarc": None,
    "has_spf": True,
    "has_dmarc": False,
    "has_caa": True,
    "findings": [
        {
            "title": "Missing DMARC Record",
            "description": "No DMARC record found.",
            "severity": "medium",
            "category": "dns",
            "recommendation": "Add a DMARC record.",
        },
    ],
}


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
    """TestClient with realistic mock scanner results."""
    with (
        patch("app.routers.scans.scan_ssl", new=AsyncMock(return_value=MOCK_SSL)),
        patch("app.routers.scans.scan_headers", new=AsyncMock(return_value=MOCK_HEADERS)),
        patch("app.routers.scans.scan_ports", new=AsyncMock(return_value=MOCK_PORTS)),
        patch("app.routers.scans.scan_endpoints", new=AsyncMock(return_value=MOCK_ENDPOINTS)),
        patch("app.routers.scans.scan_dns", new=AsyncMock(return_value=MOCK_DNS)),
        patch("app.tasks.run_scan.delay", side_effect=Exception("celery disabled")),
        patch("app.database.SessionLocal", TestSessionLocal),
    ):
        yield TestClient(app)


class TestScoringIntegration:
    """Test that aggregate_findings and compute_risk_score work together correctly."""

    def test_aggregate_and_score_pipeline(self):
        findings = aggregate_findings(MOCK_SSL, MOCK_HEADERS, MOCK_PORTS, MOCK_ENDPOINTS, MOCK_DNS)
        # 2 high (headers) + 1 low (server disclosure) + 1 low (port 80) + 1 medium (DNS) = 5
        assert len(findings) == 5

    def test_risk_score_reflects_aggregated_findings(self):
        findings = aggregate_findings(MOCK_SSL, MOCK_HEADERS, MOCK_PORTS, MOCK_ENDPOINTS, MOCK_DNS)
        score, grade = compute_risk_score(findings)
        # 2 high (15 each=30) + 2 low (3 each=6) + 1 medium (7) = 43
        assert score == 43.0
        assert grade == "C"  # 25-44 range

    def test_score_feeds_into_pdf_report(self):
        findings = aggregate_findings(MOCK_SSL, MOCK_HEADERS, MOCK_PORTS, MOCK_ENDPOINTS, MOCK_DNS)
        score, grade = compute_risk_score(findings)
        pdf = generate_pdf_report(
            domain="example.com",
            risk_score=score,
            risk_grade=grade,
            findings=findings,
            ssl_results=MOCK_SSL,
            headers_results=MOCK_HEADERS,
            ports_results=MOCK_PORTS,
            endpoints_results=MOCK_ENDPOINTS,
            dns_results=MOCK_DNS,
        )
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF"


class TestEndToEndScanWorkflow:
    """Integration tests for the full scan workflow through the API."""

    def test_create_scan_triggers_background_processing(self, client):
        """Creating a scan should return 201 and schedule background processing."""
        resp = client.post("/api/scans", json={"domain": "example.com"})
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        # Verify the scan was created and is in a valid state
        resp = client.get(f"/api/scans/{scan_id}")
        data = resp.json()
        assert data["id"] == scan_id
        assert data["domain"] == "example.com"
        assert data["status"] in ("completed", "running", "pending")

    def test_completed_scan_has_all_result_fields(self, client):
        """A completed scan should have all result sections populated."""
        db = TestSessionLocal()
        scan = ScanModel(
            domain="full-test.com",
            status=ScanStatus.COMPLETED,
            risk_score=43.0,
            risk_grade="C",
            findings=json.dumps(
                aggregate_findings(MOCK_SSL, MOCK_HEADERS, MOCK_PORTS, MOCK_ENDPOINTS, MOCK_DNS)
            ),
            ssl_results=json.dumps(MOCK_SSL),
            headers_results=json.dumps(MOCK_HEADERS),
            ports_results=json.dumps(MOCK_PORTS),
            endpoints_results=json.dumps(MOCK_ENDPOINTS),
            dns_results=json.dumps(MOCK_DNS),
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        resp = client.get(f"/api/scans/{scan_id}")
        data = resp.json()

        assert data["status"] == "completed"
        assert data["risk_score"] == 43.0
        assert data["risk_grade"] == "C"
        assert data["ssl_results"] is not None
        assert data["headers_results"] is not None
        assert data["ports_results"] is not None
        assert data["endpoints_results"] is not None
        assert data["dns_results"] is not None
        assert data["findings"] is not None
        assert len(data["findings"]) > 0

    def test_completed_scan_pdf_report_generation(self, client):
        """PDF report should be generated from completed scan data."""
        db = TestSessionLocal()
        scan = ScanModel(
            domain="pdf-test.com",
            status=ScanStatus.COMPLETED,
            risk_score=43.0,
            risk_grade="C",
            findings=json.dumps(
                aggregate_findings(MOCK_SSL, MOCK_HEADERS, MOCK_PORTS, MOCK_ENDPOINTS, MOCK_DNS)
            ),
            ssl_results=json.dumps(MOCK_SSL),
            headers_results=json.dumps(MOCK_HEADERS),
            ports_results=json.dumps(MOCK_PORTS),
            endpoints_results=json.dumps(MOCK_ENDPOINTS),
            dns_results=json.dumps(MOCK_DNS),
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        resp = client.get(f"/api/reports/{scan_id}/pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content[:4] == b"%PDF"
        assert len(resp.content) > 1000

    def test_scan_list_includes_completed_scan(self, client):
        """Completed scans should appear in the scan list."""
        db = TestSessionLocal()
        scan = ScanModel(
            domain="listed.com",
            status=ScanStatus.COMPLETED,
            risk_score=25.0,
            risk_grade="C",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.close()

        resp = client.get("/api/scans")
        data = resp.json()
        assert data["total"] >= 1
        domains = [s["domain"] for s in data["scans"]]
        assert "listed.com" in domains

    def test_failed_scan_does_not_produce_pdf(self, client):
        """Failed scans should return 400 when requesting a PDF report."""
        db = TestSessionLocal()
        scan = ScanModel(
            domain="failed.com",
            status=ScanStatus.FAILED,
            error_message="Connection timeout",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        resp = client.get(f"/api/reports/{scan_id}/pdf")
        assert resp.status_code == 400

    def test_delete_scan_removes_from_list(self, client):
        """Deleting a scan should remove it from the list."""
        db = TestSessionLocal()
        scan = ScanModel(
            domain="to-delete.com",
            status=ScanStatus.COMPLETED,
            risk_score=10.0,
            risk_grade="B",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        # Verify it exists
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200

        # Delete it
        resp = client.delete(f"/api/scans/{scan_id}")
        assert resp.status_code == 204

        # Verify it's gone
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 404


class TestFindingsToScoreToReport:
    """Test the full pipeline: findings → scoring → PDF report."""

    def test_high_risk_domain(self):
        """A domain with many critical findings should get a high risk score and grade F."""
        ssl_bad = {
            "findings": [
                {"title": "SSL Expired", "description": "Cert expired", "severity": "critical",
                 "category": "ssl", "recommendation": "Renew cert"},
            ]
        }
        headers_bad = {
            "findings": [
                {"title": "Missing HSTS", "description": "No HSTS", "severity": "high",
                 "category": "headers", "recommendation": "Add HSTS"},
                {"title": "Missing CSP", "description": "No CSP", "severity": "high",
                 "category": "headers", "recommendation": "Add CSP"},
            ]
        }
        ports_bad = {
            "findings": [
                {"title": "MySQL exposed", "description": "Port 3306 open", "severity": "critical",
                 "category": "ports", "recommendation": "Firewall MySQL"},
                {"title": "Redis exposed", "description": "Port 6379 open", "severity": "critical",
                 "category": "ports", "recommendation": "Firewall Redis"},
            ]
        }
        eps_bad = {
            "findings": [
                {"title": "Env file exposed", "description": ".env accessible", "severity": "critical",
                 "category": "endpoints", "recommendation": "Remove .env"},
            ]
        }
        dns_bad = {
            "findings": [
                {"title": "No DNS records", "description": "No A/AAAA", "severity": "critical",
                 "category": "dns", "recommendation": "Add DNS records"},
            ]
        }

        findings = aggregate_findings(ssl_bad, headers_bad, ports_bad, eps_bad, dns_bad)
        score, grade = compute_risk_score(findings)

        assert score >= 65  # F threshold
        assert grade == "F"

        # PDF should still generate successfully
        pdf = generate_pdf_report(
            domain="insecure.example.com",
            risk_score=score,
            risk_grade=grade,
            findings=findings,
            ssl_results=None,
            headers_results=None,
            ports_results=None,
            endpoints_results=None,
            dns_results=None,
        )
        assert pdf[:4] == b"%PDF"

    def test_secure_domain(self):
        """A well-configured domain should get grade A."""
        empty_results = {"findings": []}
        findings = aggregate_findings(
            empty_results, empty_results, empty_results, empty_results, empty_results
        )
        score, grade = compute_risk_score(findings)

        assert score == 0.0
        assert grade == "A"
