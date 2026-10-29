
import os
import ssl
from datetime import UTC, datetime
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPSHandler,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Application, ScanRun, VulnerabilityFinding
from app.security_checks import (
    analyze_security_headers,
    check_local_url,
)

router = APIRouter(
    prefix="/security",
    tags=["Security Configuration Checks"],
)

REQUEST_TIMEOUT = 5
MAX_RESPONSE_BYTES = 1024


def utc_now():
    return datetime.now(UTC)


class NoRedirectHandler(HTTPRedirectHandler):
    """Do not follow redirects to another destination."""

    def redirect_request(
        self,
        request,
        file_pointer,
        code,
        message,
        headers,
        new_url,
    ):
        return None


def build_local_opener(url):
    """Build an opener with normal TLS verification.

    WEBSHIELD_LOCAL_TEST_CA_FILE is optional. When configured, it
    adds an explicitly trusted CA certificate for local HTTPS testing.
    TLS verification is never disabled.
    """
    check_local_url(url)

    handlers = [NoRedirectHandler()]

    if url.lower().startswith("https://"):
        ca_file = os.environ.get("WEBSHIELD_LOCAL_TEST_CA_FILE")

        if ca_file:
            if not os.path.isfile(ca_file):
                raise RuntimeError(
                    "Configured local test CA certificate file does not exist."
                )

            try:
                context = ssl.create_default_context(cafile=ca_file)
            except (OSError, ssl.SSLError, ValueError) as exc:
                raise RuntimeError(
                    "Could not load the configured local test CA certificate."
                ) from exc

            handlers.append(HTTPSHandler(context=context))

    return build_opener(*handlers)


def fetch_local_headers(url):
    """Fetch headers from a registered local lab application."""
    check_local_url(url)

    request = Request(
        url,
        method="GET",
        headers={"User-Agent": "WebShield-Local-Checker/1.0"},
    )

    opener = build_local_opener(url)
    started = perf_counter()

    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            status_code = response.status
            headers = response.headers
            response.read(MAX_RESPONSE_BYTES)

    except HTTPError as exc:
        # Redirects are returned here because following them is disabled.
        status_code = exc.code
        headers = exc.headers
        exc.close()

    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        raise RuntimeError(
            f"Local target request failed: {type(exc).__name__}"
        ) from exc

    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    return status_code, headers, elapsed_ms


@router.post("/applications/{application_id}/check-headers")
def check_application_security_headers(
    application_id: int,
    db: Session = Depends(get_db),
):
    """Check and save security configuration observations."""
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

    try:
        check_local_url(application.base_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Only registered local lab URLs are permitted.",
        ) from exc

    now = utc_now()

    scan = ScanRun(
        application_id=application.id,
        status="RUNNING",
        scanner="webshield-security-checker",
        started_at=now,
    )

    db.add(scan)

    try:
        db.flush()

        status_code, headers, elapsed_ms = fetch_local_headers(
            application.base_url
        )

        result = analyze_security_headers(
            url=application.base_url,
            status_code=status_code,
            headers=headers,
        )

        saved_findings = []

        for item in result["findings"]:
            finding = VulnerabilityFinding(
                scan_id=scan.id,
                title=item["title"][:200],
                severity=item["severity"],
                affected_url=item["affected_url"][:1000],
                description=item["description"],
                evidence=item.get("evidence"),
                remediation=item.get("remediation"),
                status="OPEN",
                source="webshield-security-checker",
                first_seen_at=now,
                last_seen_at=now,
            )

            db.add(finding)
            saved_findings.append(finding)

        scan.status = "COMPLETED"
        scan.completed_at = utc_now()

        db.commit()

        for finding in saved_findings:
            db.refresh(finding)

        db.refresh(scan)

        return {
            "message": "Security configuration check completed.",
            "application_id": application.id,
            "application_name": application.name,
            "target_url": application.base_url,
            "scan_id": scan.id,
            "scan_status": scan.status,
            "scanner": scan.scanner,
            "http_status": status_code,
            "elapsed_ms": elapsed_ms,
            "findings_count": len(saved_findings),
            "findings": [
                {
                    "id": finding.id,
                    "scan_id": finding.scan_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "affected_url": finding.affected_url,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "status": finding.status,
                    "source": finding.source,
                }
                for finding in saved_findings
            ],
            "note": (
                "These are security configuration observations, not "
                "independent proof of exploitable vulnerabilities."
            ),
        }

    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=(
                "Could not complete and save the security check. "
                f"Error type: {type(exc).__name__}"
            ),
        ) from exc

