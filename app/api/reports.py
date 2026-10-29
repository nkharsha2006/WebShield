from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Application,
    ScanRun,
    VerificationAttempt,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


def finding_match_key(
    finding: VulnerabilityFinding,
) -> tuple[str, str, str]:
    """Normalize a finding key consistently with scan comparison."""
    return (
        (finding.title or "").strip().rstrip("/").casefold(),
        (finding.affected_url or "").strip().rstrip("/").casefold(),
        (finding.source or "").strip().rstrip("/").casefold(),
    )


def isoformat(value):
    if value is None:
        return None
    return value.isoformat()


def normalize_datetime(value: datetime) -> datetime:
    """Normalize potentially timezone-naive SQLite datetimes to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@router.get("/applications/{application_id}")
def application_report(
    application_id: int,
    db: Session = Depends(get_db),
):
    """Build a JSON remediation report for one application."""
    application = db.query(Application).filter(Application.id == application_id).first()

    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found",
        )

    scans = (
        db.query(ScanRun)
        .filter(ScanRun.application_id == application_id)
        .order_by(ScanRun.id.asc())
        .all()
    )
    scans_by_id = {scan.id: scan for scan in scans}
    scan_ids = list(scans_by_id)

    findings = []
    if scan_ids:
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.scan_id.in_(scan_ids))
            .order_by(VulnerabilityFinding.id.asc())
            .all()
        )

    finding_ids = [finding.id for finding in findings]
    attempts = []

    if finding_ids:
        attempts = (
            db.query(VerificationAttempt)
            .filter(VerificationAttempt.finding_id.in_(finding_ids))
            .order_by(VerificationAttempt.verified_at.asc())
            .all()
        )

    findings_by_id = {finding.id: finding for finding in findings}
    attempts_by_finding = {}

    for attempt in attempts:
        attempts_by_finding.setdefault(attempt.finding_id, []).append(attempt)

    # Store the latest verified resolution for each issue:
    # (verification timestamp, verification scan ID).
    verified_resolutions = {}

    for attempt in attempts:
        if attempt.outcome != "VERIFIED_RESOLVED" or attempt.verified_at is None:
            continue

        original = findings_by_id.get(attempt.finding_id)
        verification_scan = scans_by_id.get(attempt.verification_scan_id)

        if (
            original is None
            or verification_scan is None
            or verification_scan.status != "COMPLETED"
            or verification_scan.application_id != application_id
        ):
            continue

        key = finding_match_key(original)
        resolved_at = normalize_datetime(attempt.verified_at)
        previous = verified_resolutions.get(key)

        if previous is None or resolved_at > previous[0]:
            verified_resolutions[key] = (
                resolved_at,
                verification_scan.id,
            )

    # Select the latest finding record for each issue in completed scans.
    latest_by_key = {}

    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)

        if scan is None or scan.status != "COMPLETED":
            continue

        key = finding_match_key(finding)
        current = latest_by_key.get(key)

        if current is None or scan.id > current[0].id:
            latest_by_key[key] = (scan, finding)

    # A regression must occur in a scan after the verification scan
    # and after the recorded verification timestamp.
    regressions = []

    for key, (scan, finding) in latest_by_key.items():
        resolution = verified_resolutions.get(key)

        if resolution is None or scan.started_at is None:
            continue

        resolved_at, verification_scan_id = resolution

        # Scan IDs establish the workflow order; timestamps provide
        # an additional safeguard against incorrectly ordered records.
        if scan.id <= verification_scan_id:
            continue

        scan_started = normalize_datetime(scan.started_at)

        if scan_started <= resolved_at:
            continue

        regressions.append(
            {
                "finding_id": finding.id,
                "scan_id": scan.id,
                "title": finding.title,
                "severity": finding.severity,
                "affected_url": finding.affected_url,
                "source": finding.source,
                "status": finding.status,
                "note": (
                    "A matching issue was detected in the latest "
                    "completed scan after its most recent verified "
                    "resolution. Review the scan and verification "
                    "evidence before confirming a regression."
                ),
            }
        )

    finding_records = []
    counts_by_status = {}
    counts_by_severity = {}

    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)

        finding_records.append(
            {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "scan_status": scan.status if scan else None,
                "title": finding.title,
                "severity": finding.severity,
                "affected_url": finding.affected_url,
                "description": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "status": finding.status,
                "source": finding.source,
                "first_seen_at": isoformat(finding.first_seen_at),
                "last_seen_at": isoformat(finding.last_seen_at),
                "verification_history": [
                    {
                        "id": attempt.id,
                        "verification_scan_id": attempt.verification_scan_id,
                        "outcome": attempt.outcome,
                        "evidence": attempt.evidence,
                        "note": attempt.note,
                        "verified_at": isoformat(attempt.verified_at),
                    }
                    for attempt in attempts_by_finding.get(finding.id, [])
                ],
            }
        )

        # These counts represent historical records, not unique live issues.
        counts_by_status[finding.status] = counts_by_status.get(finding.status, 0) + 1
        counts_by_severity[finding.severity] = (
            counts_by_severity.get(finding.severity, 0) + 1
        )

    scan_records = [
        {
            "id": scan.id,
            "status": scan.status,
            "scanner": scan.scanner,
            "started_at": isoformat(scan.started_at),
            "completed_at": isoformat(scan.completed_at),
            "error_message": scan.error_message,
        }
        for scan in scans
    ]

    report = {
        "report_type": "WebShield Application Remediation Report",
        "generated_at": datetime.now(UTC).isoformat(),
        "application": {
            "id": application.id,
            "name": application.name,
            "base_url": application.base_url,
            "is_active": application.is_active,
            "created_at": isoformat(application.created_at),
        },
        "summary": {
            "total_scans": len(scans),
            "completed_scans": sum(scan.status == "COMPLETED" for scan in scans),
            "failed_scans": sum(scan.status == "FAILED" for scan in scans),
            "total_recorded_findings": len(findings),
            "findings_by_status": counts_by_status,
            "findings_by_severity": counts_by_severity,
            "verification_attempts": len(attempts),
            "regression_candidates": len(regressions),
        },
        "scans": scan_records,
        "findings": finding_records,
        "regressions": regressions,
        "limitations": [
            "This report summarizes records stored by WebShield.",
            (
                "Finding status counts describe historical finding records, "
                "not unique currently active issues."
            ),
            ("A finding absent from a scan is not automatically proof of remediation."),
            (
                "Regression candidates require review of scan timing "
                "and verification evidence."
            ),
            (
                "Security configuration observations are not independent "
                "proof of exploitability."
            ),
        ],
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": (
                f'attachment; filename="webshield-application-'
                f'{application_id}-report.json"'
            )
        },
    )
