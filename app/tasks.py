"""Celery background tasks for asynchronous scan processing."""

import asyncio
import json
import logging
from datetime import datetime, timezone

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import ScanModel, ScanStatus
from app.scanners.ssl_scanner import scan_ssl
from app.scanners.headers_scanner import scan_headers
from app.scanners.port_scanner import scan_ports
from app.scanners.endpoint_scanner import scan_endpoints
from app.scanners.dns_scanner import scan_dns
from app.scanners.scoring import aggregate_findings, compute_risk_score

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine in a fresh event loop (for Celery worker context)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, name="app.tasks.run_scan", max_retries=1)
def run_scan(self, scan_id: int) -> dict:
    """
    Background task that performs all security scans for a given scan record.
    """
    db = SessionLocal()
    try:
        scan: ScanModel = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        domain = scan.domain
        logger.info("Starting scan for domain: %s (id=%s)", domain, scan_id)

        try:
            ssl_results = _run_async(scan_ssl(domain))
            headers_results = _run_async(scan_headers(domain))
            ports_results = _run_async(scan_ports(domain))
            endpoints_results = _run_async(scan_endpoints(domain))
            dns_results = _run_async(scan_dns(domain))

            findings = aggregate_findings(
                ssl_results, headers_results, ports_results, endpoints_results, dns_results
            )
            risk_score, risk_grade = compute_risk_score(findings)

            scan.ssl_results = json.dumps(ssl_results)
            scan.headers_results = json.dumps(headers_results)
            scan.ports_results = json.dumps(ports_results)
            scan.endpoints_results = json.dumps(endpoints_results)
            scan.dns_results = json.dumps(dns_results)
            scan.findings = json.dumps(findings)
            scan.risk_score = risk_score
            scan.risk_grade = risk_grade
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)

        db.commit()
        return {"scan_id": scan_id, "status": scan.status.value}

    finally:
        db.close()
