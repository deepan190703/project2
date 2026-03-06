"""Scan management API routes."""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanModel, ScanStatus
from app.schemas import ScanCreate, ScanListResponse, ScanResponse, Finding
from app.scanners.scoring import aggregate_findings, compute_risk_score
from app.scanners.ssl_scanner import scan_ssl
from app.scanners.headers_scanner import scan_headers
from app.scanners.port_scanner import scan_ports
from app.scanners.endpoint_scanner import scan_endpoints
from app.scanners.dns_scanner import scan_dns

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Internal helper – run scan in-process using FastAPI BackgroundTasks
# ---------------------------------------------------------------------------

async def _perform_scan(scan_id: int, domain: str):
    """Execute all scanner modules and persist results.

    Opens a fresh DB session so the background task is not coupled to the
    request-scoped session (which may close before the task completes).
    """
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        scan: Optional[ScanModel] = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            ssl_results = await scan_ssl(domain)
            headers_results = await scan_headers(domain)
            ports_results = await scan_ports(domain)
            endpoints_results = await scan_endpoints(domain)
            dns_results = await scan_dns(domain)

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
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Submit a new domain scan. The scan runs asynchronously in the background."""
    scan = ScanModel(domain=payload.domain, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Try to dispatch via Celery; fall back to FastAPI background task
    try:
        from app.tasks import run_scan
        run_scan.delay(scan.id)
    except Exception:
        background_tasks.add_task(_perform_scan, scan.id, scan.domain)

    return _build_response(scan)


@router.get("", response_model=ScanListResponse)
def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    """Return a paginated list of all scans."""
    total = db.query(ScanModel).count()
    scans = (
        db.query(ScanModel)
        .order_by(ScanModel.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return ScanListResponse(total=total, scans=scans)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve full results for a single scan."""
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _build_response(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan record."""
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _build_response(scan: ScanModel) -> ScanResponse:
    findings_raw = scan.get_findings()
    findings = [Finding(**f) for f in findings_raw] if findings_raw else []
    return ScanResponse(
        id=scan.id,
        domain=scan.domain,
        status=scan.status,
        risk_score=scan.risk_score,
        risk_grade=scan.risk_grade,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        ssl_results=scan.get_ssl_results(),
        headers_results=scan.get_headers_results(),
        ports_results=scan.get_ports_results(),
        endpoints_results=scan.get_endpoints_results(),
        dns_results=scan.get_dns_results(),
        findings=findings,
    )
