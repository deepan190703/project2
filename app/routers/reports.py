"""PDF report download route."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanModel, ScanStatus
from app.pdf_generator import generate_pdf_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/pdf")
def download_report(scan_id: int, db: Session = Depends(get_db)):
    """Generate and stream a PDF security report for a completed scan."""
    scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Report not available – scan status is '{scan.status.value}'.",
        )

    pdf_bytes = generate_pdf_report(
        domain=scan.domain,
        risk_score=scan.risk_score,
        risk_grade=scan.risk_grade,
        findings=scan.get_findings(),
        ssl_results=scan.get_ssl_results(),
        headers_results=scan.get_headers_results(),
        ports_results=scan.get_ports_results(),
        endpoints_results=scan.get_endpoints_results(),
        dns_results=scan.get_dns_results(),
    )

    filename = f"securescan_{scan.domain}_{scan.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
