from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

FindingStatus = Literal[
    "OPEN",
    "IN_PROGRESS",
    "ACCEPTED",
    "RESOLVED",
    "VERIFIED_RESOLVED",
    "FALSE_POSITIVE",
]

VerificationOutcome = Literal[
    "VERIFIED_RESOLVED",
    "STILL_PRESENT",
    "INCONCLUSIVE",
]


class FindingCreate(BaseModel):
    scan_id: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    affected_url: str = Field(min_length=1, max_length=1000)
    description: str = Field(min_length=1)
    evidence: str | None = None
    remediation: str | None = None
    status: FindingStatus = "OPEN"
    source: str = Field(default="manual", min_length=1, max_length=50)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=2000)


class VerificationCreate(BaseModel):
    verification_scan_id: int = Field(ge=1)
    outcome: VerificationOutcome
    evidence: str = Field(min_length=1, max_length=10000)
    note: str | None = Field(default=None, max_length=2000)


class VerificationRead(BaseModel):
    id: int
    finding_id: int
    verification_scan_id: int
    outcome: VerificationOutcome
    evidence: str | None
    note: str | None
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingRead(BaseModel):
    id: int
    scan_id: int
    title: str
    severity: Severity
    affected_url: str
    description: str
    evidence: str | None
    remediation: str | None
    status: FindingStatus
    source: str
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)
