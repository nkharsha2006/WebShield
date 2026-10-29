
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, aliased

from app.database import get_db
from app.finding_schemas import (
    FindingCreate,
    FindingRead,
    FindingStatusUpdate,
    VerificationCreate,
    VerificationRead,
)
from app.models import (
    ScanRun,
    VerificationAttempt,
    VulnerabilityFinding,
)

router = APIRouter(prefix="/findings", tags=["Findings"])

SECURITY_CHECKER = "webshield-security-checker"


def normalize_match_value(value: str | None) -> str:
    """Normalize values before comparing findings across scans."""
    return (value or "").strip().rstrip("/").casefold()


def scanner_identity(scanner: str | None) -> str:
    """
    Normalize dynamic ZAP scan IDs to their stable scanner type.
    """
    value = (scanner or "").strip()

    for prefix in ("owasp-zap-active:", "owasp-zap-spider:"):
        if value.startswith(prefix):
            suffix = value[len(prefix):]
            if suffix.isdigit():
                return prefix[:-1]

    return value


def finding_match_key(
    finding: VulnerabilityFinding,
) -> tuple[str, str, str]:
    """Use title, affected URL, and source to identify a matching issue."""
    return (
        normalize_match_value(finding.title),
        normalize_match_value(finding.affected_url),
        normalize_match_value(finding.source),
    )


def finding_summary(finding: VulnerabilityFinding) -> dict:
    """Return the fields used in scan-comparison responses."""
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "affected_url": finding.affected_url,
        "source": finding.source,
        "status": finding.status,
    }


@router.post(
    "",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    payload: FindingCreate,
    db: Session = Depends(get_db),
):
    scan = db.query(ScanRun).filter(
        ScanRun.id == payload.scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    if payload.status == "VERIFIED_RESOLVED":
        raise HTTPException(
            status_code=400,
            detail=(
                "VERIFIED_RESOLVED can only be assigned "
                "by remediation verification."
            ),
        )

    finding = VulnerabilityFinding(**payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
):
    query = db.query(VulnerabilityFinding)

    if scan_id is not None:
        query = query.filter(
            VulnerabilityFinding.scan_id == scan_id
        )

    return query.order_by(
        VulnerabilityFinding.id.desc()
    ).all()


@router.get("/compare/{latest_scan_id}")
def compare_scan_findings(
    latest_scan_id: int,
    previous_scan_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
):
    # 1. Validate the latest scan.
    latest_scan = db.query(ScanRun).filter(
        ScanRun.id == latest_scan_id
    ).first()

    if not latest_scan:
        raise HTTPException(
            status_code=404,
            detail="Latest scan not found",
        )

    if latest_scan.status != "COMPLETED":
        raise HTTPException(
            status_code=409,
            detail="The latest scan must be COMPLETED before comparison.",
        )

    # 2. Find or validate the previous scan.
    if previous_scan_id is None:
        eligible_scans = (
            db.query(ScanRun)
            .filter(
                ScanRun.application_id == latest_scan.application_id,
                ScanRun.status == "COMPLETED",
                ScanRun.id < latest_scan.id,
            )
            .order_by(ScanRun.id.desc())
            .all()
        )

        previous_scan = next(
            (
                scan
                for scan in eligible_scans
                if scanner_identity(scan.scanner)
                == scanner_identity(latest_scan.scanner)
            ),
            None,
        )
    else:
        previous_scan = db.query(ScanRun).filter(
            ScanRun.id == previous_scan_id
        ).first()

    if not previous_scan:
        raise HTTPException(
            status_code=404,
            detail="No eligible previous scan was found.",
        )

    if previous_scan.status != "COMPLETED":
        raise HTTPException(
            status_code=409,
            detail="The previous scan must be COMPLETED.",
        )

    if (
        previous_scan.application_id != latest_scan.application_id
        or scanner_identity(previous_scan.scanner)
        != scanner_identity(latest_scan.scanner)
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Scans must belong to the same application "
                "and use the same scanner type."
            ),
        )

    # 3. Load findings from both scans.
    previous_findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.scan_id == previous_scan.id
        )
        .all()
    )

    latest_findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.scan_id == latest_scan.id
        )
        .all()
    )

    previous_by_key = {
        finding_match_key(finding): finding
        for finding in previous_findings
    }

    latest_by_key = {
        finding_match_key(finding): finding
        for finding in latest_findings
    }

    previous_keys = set(previous_by_key)
    latest_keys = set(latest_by_key)

    recurring_items = [
        finding
        for key, finding in latest_by_key.items()
        if key in previous_keys
    ]

    resolved_candidates = [
        finding
        for key, finding in previous_by_key.items()
        if key not in latest_keys
    ]

    # 4. Find previous verified-resolution attempts.
    #
    # IMPORTANT: scanner_identity() is a Python function. Do not
    # call it on SQLAlchemy column expressions inside .filter().
    # Load scanner rows first and normalize their actual strings
    # in Python after the database query.
    VerificationScan = aliased(ScanRun)

    resolved_attempt_rows = (
        db.query(
            VerificationAttempt,
            VulnerabilityFinding,
            ScanRun,
            VerificationScan,
        )
        .join(
            VulnerabilityFinding,
            VerificationAttempt.finding_id
            == VulnerabilityFinding.id,
        )
        .join(
            ScanRun,
            VulnerabilityFinding.scan_id == ScanRun.id,
        )
        .join(
            VerificationScan,
            VerificationAttempt.verification_scan_id
            == VerificationScan.id,
        )
        .filter(
            ScanRun.application_id == latest_scan.application_id,
            VerificationAttempt.outcome == "VERIFIED_RESOLVED",
            VerificationScan.status == "COMPLETED",
            VerificationScan.application_id
            == latest_scan.application_id,
            VerificationScan.id <= previous_scan.id,
        )
        .all()
    )

    latest_scanner_type = scanner_identity(latest_scan.scanner)

    resolved_attempts = [
        (attempt, original_finding)
        for (
            attempt,
            original_finding,
            original_scan_row,
            verification_scan_row,
        ) in resolved_attempt_rows
        if (
            scanner_identity(original_scan_row.scanner)
            == latest_scanner_type
            and scanner_identity(verification_scan_row.scanner)
            == latest_scanner_type
        )
    ]

    resolved_keys = set()

    attempts_by_finding: dict[
        int, list[VerificationAttempt]
    ] = {}

    for attempt, original_finding in resolved_attempts:
        attempts_by_finding.setdefault(
            original_finding.id, []
        ).append(attempt)

    for original_finding_id, attempts in attempts_by_finding.items():
        original_finding = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.id == original_finding_id
            )
            .first()
        )

        if original_finding is None:
            continue

        attempts.sort(
            key=lambda item: (item.verified_at, item.id)
        )

        latest_attempt = attempts[-1]

        all_attempts = (
            db.query(VerificationAttempt)
            .filter(
                VerificationAttempt.finding_id
                == original_finding_id
            )
            .order_by(
                VerificationAttempt.verified_at.desc(),
                VerificationAttempt.id.desc(),
            )
            .all()
        )

        if not all_attempts:
            continue

        newest_attempt = all_attempts[0]

        if (
            newest_attempt.outcome == "VERIFIED_RESOLVED"
            and latest_attempt.outcome == "VERIFIED_RESOLVED"
        ):
            resolved_keys.add(
                finding_match_key(original_finding)
            )

    # 5. Identify regression candidates.
    regression_items = [
        finding
        for finding in latest_findings
        if (
            finding_match_key(finding) in resolved_keys
            and finding_match_key(finding) not in previous_keys
        )
    ]

    regression_keys = {
        finding_match_key(finding)
        for finding in regression_items
    }

    # Reopen previously verified findings when a regression occurs.
    reopened_original_ids = []

    if regression_keys:
        for _attempt, original_finding in resolved_attempts:
            key = finding_match_key(original_finding)

            if (
                key in regression_keys
                and original_finding.status == "VERIFIED_RESOLVED"
            ):
                original_finding.status = "OPEN"
                reopened_original_ids.append(original_finding.id)

        if reopened_original_ids:
            db.commit()

    # New findings exclude those classified as regressions.
    new_items = [
        finding
        for key, finding in latest_by_key.items()
        if key not in previous_keys
        and key not in regression_keys
    ]

    # 6. Return comparison results.
    return {
        "application_id": latest_scan.application_id,
        "previous_scan_id": previous_scan.id,
        "latest_scan_id": latest_scan.id,
        "summary": {
            "new": len(new_items),
            "recurring": len(recurring_items),
            "resolved_candidates": len(resolved_candidates),
            "regressions": len(regression_items),
        },
        "new_findings": [
            finding_summary(finding)
            for finding in new_items
        ],
        "recurring_findings": [
            finding_summary(finding)
            for finding in recurring_items
        ],
        "resolved_candidates": [
            finding_summary(finding)
            for finding in resolved_candidates
        ],
        "regressions": [
            finding_summary(finding)
            for finding in regression_items
        ],
        "reopened_original_finding_ids": sorted(
            set(reopened_original_ids)
        ),
        "note": (
            "A regression candidate is an issue that was verified "
            "as resolved and then reappeared after being absent "
            "from the previous scan. Issues present in both "
            "comparison scans are classified as recurring. Results "
            "depend on matching title, URL, and source; review the "
            "evidence before treating candidates as definitive."
        ),
    }


@router.get(
    "/{finding_id}/verifications",
    response_model=list[VerificationRead],
)
def list_verifications(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return (
        db.query(VerificationAttempt)
        .filter(
            VerificationAttempt.finding_id == finding_id
        )
        .order_by(
            VerificationAttempt.verified_at.desc(),
            VerificationAttempt.id.desc(),
        )
        .all()
    )


@router.post(
    "/{finding_id}/verify",
    response_model=VerificationRead,
    status_code=status.HTTP_201_CREATED,
)
def verify_finding(
    finding_id: int,
    payload: VerificationCreate,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    original_scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == finding.scan_id)
        .first()
    )

    if not original_scan:
        raise HTTPException(
            status_code=404,
            detail="Original scan not found",
        )

    original_scanner_type = scanner_identity(original_scan.scanner)

    if original_scanner_type == SECURITY_CHECKER:
        expected_source = SECURITY_CHECKER
    elif original_scanner_type == "owasp-zap-active":
        expected_source = "owasp-zap"
    else:
        raise HTTPException(
            status_code=409,
            detail=(
                "Verification supports WebShield security-checker findings "
                "and OWASP ZAP active-scan findings only."
            ),
        )

    if (
        normalize_match_value(finding.source)
        != normalize_match_value(expected_source)
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "The finding source does not match the supported scanner "
                "for its original scan."
            ),
        )

    verification_scan = (
        db.query(ScanRun)
        .filter(ScanRun.id == payload.verification_scan_id)
        .first()
    )

    if not verification_scan:
        raise HTTPException(
            status_code=404,
            detail="Verification scan not found",
        )

    if verification_scan.status != "COMPLETED":
        raise HTTPException(
            status_code=409,
            detail="Verification scan must be COMPLETED.",
        )

    if verification_scan.application_id != original_scan.application_id:
        raise HTTPException(
            status_code=400,
            detail="Verification scan must belong to the same application.",
        )

    if scanner_identity(verification_scan.scanner) != original_scanner_type:
        raise HTTPException(
            status_code=400,
            detail=(
                "Verification scan must use the same scanner type as the "
                "original scan. For ZAP findings, use a completed ZAP active scan."
            ),
        )

    if verification_scan.id <= original_scan.id:
        raise HTTPException(
            status_code=400,
            detail="Verification scan must be later than the original scan.",
        )

    verification_findings = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.scan_id == verification_scan.id)
        .all()
    )

    target_key = finding_match_key(finding)

    matching_finding = next(
        (
            item
            for item in verification_findings
            if finding_match_key(item) == target_key
        ),
        None,
    )

    if matching_finding:
        outcome = "STILL_PRESENT"
        evidence = (
            f"Completed verification scan {verification_scan.id} detected "
            f"the same issue. Matching finding ID: {matching_finding.id}; "
            f"title: {matching_finding.title}; affected URL: "
            f"{matching_finding.affected_url}; source: "
            f"{matching_finding.source}."
        )
        finding.status = "OPEN"
    else:
        outcome = "VERIFIED_RESOLVED"

        scanner_label = (
            "WebShield security configuration checker"
            if original_scanner_type == SECURITY_CHECKER
            else "OWASP ZAP active scanner"
        )

        evidence = (
            f"Completed verification scan {verification_scan.id} did not "
            f"report a matching finding using the {scanner_label}. This is "
            "evidence that this scanner did not detect the recorded issue "
            "during this scan; it is not proof that the vulnerability is "
            "completely absent. Review the scan scope and evidence before "
            "relying on this result."
        )
        finding.status = "VERIFIED_RESOLVED"

    attempt = VerificationAttempt(
        finding_id=finding.id,
        verification_scan_id=verification_scan.id,
        outcome=outcome,
        evidence=evidence,
        note=payload.note,
        verified_at=datetime.now(UTC),
    )

    db.add(attempt)
    db.add(finding)
    db.commit()
    db.refresh(attempt)

    return attempt


@router.patch(
    "/{finding_id}/status",
    response_model=FindingRead,
)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    if payload.status == "VERIFIED_RESOLVED":
        raise HTTPException(
            status_code=409,
            detail=(
                "Use the remediation verification workflow "
                "to set VERIFIED_RESOLVED."
            ),
        )

    if (
        finding.status == "VERIFIED_RESOLVED"
        and payload.status not in {"OPEN", "IN_PROGRESS"}
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "A verified finding can only be reopened "
                "as OPEN or IN_PROGRESS."
            ),
        )

    finding.status = payload.status
    db.commit()
    db.refresh(finding)

    return finding


@router.get(
    "/{finding_id}",
    response_model=FindingRead,
)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding
