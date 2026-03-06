"""SQLAlchemy ORM models."""

import enum
import json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, Enum as SAEnum

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    risk_score = Column(Float, nullable=True)
    risk_grade = Column(String(2), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # JSON-serialised results for each scanner module
    ssl_results = Column(Text, nullable=True)
    headers_results = Column(Text, nullable=True)
    ports_results = Column(Text, nullable=True)
    endpoints_results = Column(Text, nullable=True)
    dns_results = Column(Text, nullable=True)

    # Aggregated list of findings (JSON)
    findings = Column(Text, nullable=True)

    def get_ssl_results(self):
        return json.loads(self.ssl_results) if self.ssl_results else None

    def get_headers_results(self):
        return json.loads(self.headers_results) if self.headers_results else None

    def get_ports_results(self):
        return json.loads(self.ports_results) if self.ports_results else None

    def get_endpoints_results(self):
        return json.loads(self.endpoints_results) if self.endpoints_results else None

    def get_dns_results(self):
        return json.loads(self.dns_results) if self.dns_results else None

    def get_findings(self):
        return json.loads(self.findings) if self.findings else []
