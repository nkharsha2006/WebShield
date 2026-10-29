
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Application, ScanRun, VulnerabilityFinding
from app.scan_schemas import ScanRunRead
from app.zap_client import ZapClient, ZapClientError


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/zap", tags=["OWASP ZAP Scanning"])


def utc_now():
    return datetime.now(UTC)


def map_severity(risk):
    mapping = {
        "informational": "INFO",
        "info": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }
    if not isinstance(risk, str):
        return "INFO"
    return mapping.get(risk.strip().lower(), "INFO")


def fail_scan(db, scan, message):
    scan.status = "FAILED"
    scan.completed_at = utc_now()
    scan.error_message = message[:2000]
    db.commit()


@router.post("/applications/{application_id}/scan", status_code=201)
def start_zap_scan(
    application_id: int,
    db: Session = Depends(get_db),
):
    application = db.get(Application, application_id)

    if application is None:
        raise HTTPException(404, "Application not found.")

    if not application.is_active:
        raise HTTPException(409, "Application is inactive.")

    client = ZapClient()

    try:
        target = client.validate_target(application.base_url)
        version = client.get_version()
    except ZapClientError as exc:
        logger.exception(
            "ZAP preflight failed for application_id=%s",
            application_id,
        )
        raise HTTPException(
            502, "ZAP preflight failed. Check the backend logs."
        ) from exc

    scan = ScanRun(
        application_id=application.id,
        status="QUEUED",
        scanner="owasp-zap",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = scan.id

    try:
        spider_id = client.start_spider(target)
        scan.status = "RUNNING"
        scan.scanner = f"owasp-zap-spider:{spider_id}"
        scan.started_at = utc_now()
        db.commit()
        db.refresh(scan)

    except Exception as exc:
        logger.exception(
            "Could not start ZAP Spider for application_id=%s, scan_id=%s",
            application_id,
            scan_id,
        )
        db.rollback()

        scan = db.get(ScanRun, scan_id)
        if scan is not None:
            try:
                fail_scan(
                    db,
                    scan,
                    f"Could not start ZAP Spider: {type(exc).__name__}",
                )
            except Exception:
                db.rollback()
                logger.exception(
                    "Could not persist Spider startup failure for scan_id=%s",
                    scan_id,
                )

        raise HTTPException(
            502,
            "Could not start the ZAP Spider. Check the backend logs.",
        ) from exc

    return {
        "message": "ZAP Spider started.",
        "application_id": application.id,
        "application_name": application.name,
        "target_url": target,
        "zap_version": version,
        "scan": ScanRunRead.model_validate(scan).model_dump(),
        "next_step": "Poll GET /zap/scans/{scan_id}/status for progress.",
    }


@router.get("/scans/{scan_id}/status")
def get_zap_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = db.get(ScanRun, scan_id)

    if scan is None:
        raise HTTPException(404, "Scan not found.")

    if not scan.scanner.startswith("owasp-zap-"):
        raise HTTPException(
            409, "This scan was not created by the ZAP scan workflow."
        )

    if scan.status in {"COMPLETED", "FAILED"}:
        return {
            "scan": ScanRunRead.model_validate(scan).model_dump(),
            "progress": 100 if scan.status == "COMPLETED" else None,
            "stage": scan.status.lower(),
            "findings_imported": (
                db.query(VulnerabilityFinding)
                .filter(VulnerabilityFinding.scan_id == scan.id)
                .count()
            ),
        }

    application = db.get(Application, scan.application_id)

    if application is None:
        fail_scan(db, scan, "Registered application no longer exists.")
        raise HTTPException(404, "Application not found.")

    if not application.is_active:
        fail_scan(db, scan, "Application was deactivated during the scan.")
        raise HTTPException(409, "Application is inactive.")

    client = ZapClient()

    try:
        target = client.validate_target(application.base_url)

        if scan.scanner.startswith("owasp-zap-spider:"):
            spider_id = scan.scanner.split(":", 1)[1]
            spider_progress = client.get_spider_status(spider_id)

            if spider_progress < 100:
                return {
                    "scan": ScanRunRead.model_validate(scan).model_dump(),
                    "stage": "spider",
                    "progress": spider_progress,
                    "message": "ZAP is crawling the local application.",
                }

            active_id = client.start_active_scan(target)
            scan.scanner = f"owasp-zap-active:{active_id}"
            db.commit()
            db.refresh(scan)

            return {
                "scan": ScanRunRead.model_validate(scan).model_dump(),
                "stage": "active_scan",
                "progress": 0,
                "message": "Spider finished. Active Scan has started.",
            }

        if scan.scanner.startswith("owasp-zap-active:"):
            active_id = scan.scanner.split(":", 1)[1]
            progress = client.get_active_scan_status(active_id)

            if progress < 100:
                return {
                    "scan": ScanRunRead.model_validate(scan).model_dump(),
                    "stage": "active_scan",
                    "progress": progress,
                    "message": "ZAP Active Scan is running.",
                }

            alerts = client.get_alerts(base_url=target)
            now = utc_now()
            seen = set()
            imported = 0

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue

                title = str(
                    alert.get("name") or alert.get("alert") or ""
                ).strip()
                affected_url = str(alert.get("url") or "").strip()

                if not title or not affected_url:
                    continue

                key = (
                    str(alert.get("pluginId", "")),
                    title,
                    affected_url,
                    str(alert.get("param", "")),
                )

                if key in seen:
                    continue

                seen.add(key)

                db.add(
                    VulnerabilityFinding(
                        scan_id=scan.id,
                        title=title[:200],
                        severity=map_severity(alert.get("risk")),
                        affected_url=affected_url[:1000],
                        description=str(
                            alert.get("description")
                            or "Description was not provided by ZAP."
                        ),
                        evidence=(
                            str(alert.get("evidence") or "").strip() or None
                        ),
                        remediation=(
                            str(alert.get("solution") or "").strip() or None
                        ),
                        status="OPEN",
                        source="owasp-zap",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
                imported += 1

            scan.status = "COMPLETED"
            scan.completed_at = utc_now()
            scan.error_message = None
            db.commit()
            db.refresh(scan)

            return {
                "scan": ScanRunRead.model_validate(scan).model_dump(),
                "stage": "completed",
                "progress": 100,
                "findings_imported": imported,
                "message": "Scan completed and findings saved to WebShield.",
            }

        raise ZapClientError("Unknown ZAP scan stage.")

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(
            "ZAP status processing failed for scan_id=%s, scanner=%s",
            scan_id,
            scan.scanner,
        )

        db.rollback()
        scan = db.get(ScanRun, scan_id)

        if scan is not None and scan.status not in {"COMPLETED", "FAILED"}:
            try:
                fail_scan(
                    db,
                    scan,
                    f"ZAP scan processing failed: {type(exc).__name__}",
                )
            except Exception:
                db.rollback()
                logger.exception(
                    "Could not persist ZAP scan failure for scan_id=%s",
                    scan_id,
                )

        raise HTTPException(
            502,
            "Could not process ZAP scan status. Check the backend logs.",
        ) from exc
