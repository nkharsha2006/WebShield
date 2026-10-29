import hashlib
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Application,
    ScanRun,
    VulnerabilityFinding,
    ZapImportBatch,
)
from app.zap_client import ZapClient, ZapClientError

router = APIRouter(
    prefix="/zap",
    tags=["OWASP ZAP Integration"],
)

ZAP_ALERT_PAGE_SIZE = 100
MAX_ZAP_ALERT_PAGES = 1000


def utc_now():
    return datetime.now(UTC)


def map_severity(risk):
    """Convert ZAP risk labels into WebShield severity values."""

    if not isinstance(risk, str):
        return "INFO"

    normalized = risk.strip().lower()

    mapping = {
        "informational": "INFO",
        "info": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }

    return mapping.get(normalized, "INFO")


def fetch_all_alerts(client, base_url):
    """Retrieve all ZAP alert pages without silently truncating results."""

    all_alerts = []
    start = 0

    for _ in range(MAX_ZAP_ALERT_PAGES):
        page = client.get_alerts(
            base_url=base_url,
            start=start,
            count=ZAP_ALERT_PAGE_SIZE,
        )

        if not isinstance(page, list):
            raise ZapClientError("ZAP returned an invalid alerts page.")

        all_alerts.extend(page)

        if len(page) < ZAP_ALERT_PAGE_SIZE:
            return all_alerts

        start += len(page)

    raise ZapClientError(
        "ZAP alert pagination exceeded the safety limit. "
        "No import was saved."
    )


def normalize_alerts(alerts):
    """Validate, normalize, and deduplicate the collected ZAP alerts."""

    normalized_alerts = []
    seen = set()
    skipped = 0

    for alert in alerts:
        if not isinstance(alert, dict):
            skipped += 1
            continue

        title = str(
            alert.get("name") or alert.get("alert") or "Unnamed ZAP alert"
        ).strip()
        affected_url = str(alert.get("url") or "").strip()

        if not title or not affected_url:
            skipped += 1
            continue

        alert_key = (
            str(alert.get("pluginId", "")),
            title,
            affected_url,
            str(alert.get("param", "")),
        )

        if alert_key in seen:
            skipped += 1
            continue

        seen.add(alert_key)

        normalized_alerts.append(
            {
                "plugin_id": str(alert.get("pluginId", "")),
                "title": title[:200],
                "affected_url": affected_url[:1000],
                "severity": map_severity(alert.get("risk")),
                "description": str(
                    alert.get("description")
                    or "Description was not provided by ZAP."
                ),
                "evidence": str(alert.get("evidence") or "").strip() or None,
                "remediation": str(alert.get("solution") or "").strip() or None,
                "parameter": str(alert.get("param", "")),
            }
        )

    # Sorting makes the fingerprint independent of alert ordering.
    normalized_alerts.sort(
        key=lambda item: (
            item["plugin_id"],
            item["title"],
            item["affected_url"],
            item["parameter"],
            item["severity"],
            item["evidence"] or "",
        )
    )

    return normalized_alerts, skipped


def calculate_fingerprint(normalized_alerts):
    """Create a stable SHA-256 fingerprint for normalized alert content."""

    canonical_json = json.dumps(
        normalized_alerts,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@router.post("/applications/{application_id}/import-alerts")
def import_zap_alerts(
    application_id: int,
    db: Session = Depends(get_db),
):
    """Import existing ZAP alerts for a registered local lab application."""

    application = db.get(Application, application_id)

    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found.",
        )

    if not application.is_active:
        raise HTTPException(
            status_code=409,
            detail="Application is inactive.",
        )

    client = ZapClient()

    try:
        zap_version = client.get_version()
        alerts = fetch_all_alerts(client, application.base_url)
    except ZapClientError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    normalized_alerts, skipped = normalize_alerts(alerts)
    fingerprint = calculate_fingerprint(normalized_alerts)

    existing_batch = db.scalar(
        select(ZapImportBatch).where(
            ZapImportBatch.application_id == application.id,
            ZapImportBatch.fingerprint == fingerprint,
        )
    )

    if existing_batch is not None:
        existing_scan = db.get(ScanRun, existing_batch.scan_id)

        if existing_scan is not None:
            return {
                "message": "Identical ZAP alert response was already imported.",
                "application_id": application.id,
                "application_name": application.name,
                "zap_version": zap_version,
                "scan_id": existing_scan.id,
                "scan_status": existing_scan.status,
                "alerts_returned_by_zap": len(alerts),
                "findings_imported": 0,
                "alerts_skipped": skipped,
                "duplicate_import": True,
                "note": (
                    "The existing import result was reused. "
                    "No duplicate scan or findings were created."
                ),
            }

    now = utc_now()
    scan = ScanRun(
        application_id=application.id,
        status="RUNNING",
        scanner="owasp-zap-alert-import",
        started_at=now,
    )

    try:
        db.add(scan)
        db.flush()

        for alert in normalized_alerts:
            db.add(
                VulnerabilityFinding(
                    scan_id=scan.id,
                    title=alert["title"],
                    severity=alert["severity"],
                    affected_url=alert["affected_url"],
                    description=alert["description"],
                    evidence=alert["evidence"],
                    remediation=alert["remediation"],
                    status="OPEN",
                    source="owasp-zap",
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )

        scan.status = "COMPLETED"
        scan.completed_at = utc_now()

        db.add(
            ZapImportBatch(
                application_id=application.id,
                fingerprint=fingerprint,
                scan_id=scan.id,
            )
        )

        db.commit()
        db.refresh(scan)

        return {
            "message": "ZAP alert import completed.",
            "application_id": application.id,
            "application_name": application.name,
            "zap_version": zap_version,
            "scan_id": scan.id,
            "scan_status": scan.status,
            "alerts_returned_by_zap": len(alerts),
            "findings_imported": len(normalized_alerts),
            "alerts_skipped": skipped,
            "duplicate_import": False,
            "note": (
                "Imported alerts are scanner results, not "
                "independent confirmation that vulnerabilities exist. "
                "No scan was started by this endpoint."
            ),
        }

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "A matching ZAP import was recorded concurrently. "
                "Retry the request to retrieve the existing result."
            ),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=(
                "Could not save ZAP alerts to the WebShield database. "
                f"Error type: {type(exc).__name__}"
            ),
        ) from exc
