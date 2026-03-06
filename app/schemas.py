"""Pydantic schemas for request/response validation."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, field_validator

from app.models import ScanStatus


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = v.strip().lower()
        # Strip protocol if provided
        for prefix in ("https://", "http://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        # Strip trailing slash/path
        v = v.split("/")[0]
        if not v:
            raise ValueError("Domain cannot be empty")
        return v


# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    title: str
    description: str
    severity: str          # critical / high / medium / low / info
    category: str          # ssl / headers / ports / endpoints / dns
    recommendation: str


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    id: int
    domain: str
    status: ScanStatus
    risk_score: Optional[float] = None
    risk_grade: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    ssl_results: Optional[Dict[str, Any]] = None
    headers_results: Optional[Dict[str, Any]] = None
    ports_results: Optional[Dict[str, Any]] = None
    endpoints_results: Optional[Dict[str, Any]] = None
    dns_results: Optional[Dict[str, Any]] = None
    findings: Optional[List[Finding]] = None

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: int
    domain: str
    status: ScanStatus
    risk_score: Optional[float] = None
    risk_grade: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanListItem]
