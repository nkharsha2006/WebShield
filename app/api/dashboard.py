from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Application,
    ScanRun,
    VerificationAttempt,
    VulnerabilityFinding,
)

router = APIRouter(tags=["Dashboard"])


def to_iso(value):
    if value is None:
        return None
    return value.isoformat()


def finding_match_key(finding):
    """Match findings using the same fields as the comparison workflow."""
    return (
        (finding.title or "").strip().rstrip("/").casefold(),
        (finding.affected_url or "").strip().rstrip("/").casefold(),
        (finding.source or "").strip().rstrip("/").casefold(),
    )


@router.get("/dashboard/data")
def dashboard_data(db: Session = Depends(get_db)):
    applications = db.query(Application).order_by(Application.id.asc()).all()

    scans = db.query(ScanRun).order_by(ScanRun.id.desc()).all()

    findings = (
        db.query(VulnerabilityFinding).order_by(VulnerabilityFinding.id.desc()).all()
    )

    attempts = (
        db.query(VerificationAttempt)
        .order_by(VerificationAttempt.verified_at.asc())
        .all()
    )

    scans_by_id = {scan.id: scan for scan in scans}
    applications_by_id = {application.id: application for application in applications}

    completed_scans = [scan for scan in scans if scan.status == "COMPLETED"]

    # The dashboard counts stored finding records, not unique live issues.
    findings_by_status = {}
    findings_by_severity = {}

    for finding in findings:
        findings_by_status[finding.status] = (
            findings_by_status.get(finding.status, 0) + 1
        )
        findings_by_severity[finding.severity] = (
            findings_by_severity.get(finding.severity, 0) + 1
        )

    # Find issues with a recorded verified resolution.
    verified_resolution_times = {}

    for attempt in attempts:
        if attempt.outcome != "VERIFIED_RESOLVED":
            continue

        original = next(
            (item for item in findings if item.id == attempt.finding_id),
            None,
        )
        if original is None:
            continue

        key = finding_match_key(original)
        if attempt.verified_at is None:
            continue

        previous = verified_resolution_times.get(key)
        if previous is None or attempt.verified_at > previous:
            verified_resolution_times[key] = attempt.verified_at

    # For each finding key, inspect the latest completed scan record.
    latest_by_key = {}

    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)
        if scan is None or scan.status != "COMPLETED":
            continue

        key = finding_match_key(finding)
        current = latest_by_key.get(key)

        if current is None or scan.id > current[0]:
            latest_by_key[key] = (scan.id, finding)

    regressions = []

    for key, (scan_id, finding) in latest_by_key.items():
        resolved_at = verified_resolution_times.get(key)
        scan = scans_by_id.get(scan_id)

        if resolved_at is None or scan is None or scan.started_at is None:
            continue

        # SQLite may return timezone-naive datetimes even when the model
        # declares timezone support. Normalize both values for comparison.
        scan_started = scan.started_at
        if scan_started.tzinfo is None:
            scan_started = scan_started.replace(tzinfo=UTC)

        resolved_time = resolved_at
        if resolved_time.tzinfo is None:
            resolved_time = resolved_time.replace(tzinfo=UTC)

        if scan_started > resolved_time:
            regressions.append(
                {
                    "finding_id": finding.id,
                    "scan_id": scan_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "affected_url": finding.affected_url,
                    "source": finding.source,
                    "status": finding.status,
                }
            )

    recent_scans = []
    for scan in scans[:8]:
        application = applications_by_id.get(scan.application_id)
        recent_scans.append(
            {
                "id": scan.id,
                "application_id": scan.application_id,
                "application_name": (
                    application.name if application else "Unknown application"
                ),
                "status": scan.status,
                "scanner": scan.scanner,
                "started_at": to_iso(scan.started_at),
                "completed_at": to_iso(scan.completed_at),
            }
        )

    recent_findings = []
    for finding in findings[:10]:
        recent_findings.append(
            {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "source": finding.source,
                "affected_url": finding.affected_url,
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_applications": len(applications),
            "active_applications": sum(
                application.is_active for application in applications
            ),
            "total_scans": len(scans),
            "completed_scans": len(completed_scans),
            "failed_scans": sum(scan.status == "FAILED" for scan in scans),
            "total_recorded_findings": len(findings),
            "findings_by_status": findings_by_status,
            "findings_by_severity": findings_by_severity,
            "verification_attempts": len(attempts),
            "regression_candidates": len(regressions),
        },
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
        "regressions": regressions,
    }
