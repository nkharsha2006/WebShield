from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import (
    Application,
    ScanRun,
    VerificationAttempt,
    VulnerabilityFinding,
)


@pytest.fixture
def report_environment():
    """Create an isolated in-memory database for report tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client, TestSession
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def create_scan(db, application_id, scan_id, status="COMPLETED"):
    """Create a scan record for testing."""
    started = datetime.now(UTC) + timedelta(seconds=scan_id)
    scan = ScanRun(
        id=scan_id,
        application_id=application_id,
        status=status,
        scanner="webshield-security-checker",
        started_at=started,
        completed_at=(
            started + timedelta(seconds=1) if status == "COMPLETED" else None
        ),
    )
    db.add(scan)
    db.flush()
    return scan


def create_finding(db, scan_id, status="OPEN"):
    """Create a finding record for testing."""
    finding = VulnerabilityFinding(
        scan_id=scan_id,
        title="X-Content-Type-Options Header Missing",
        severity="LOW",
        affected_url="http://127.0.0.1:3000",
        description="The response lacks the expected security header.",
        evidence="Test evidence.",
        remediation="Set X-Content-Type-Options: nosniff.",
        status=status,
        source="webshield-security-checker",
    )
    db.add(finding)
    db.flush()
    return finding


def test_report_includes_scan_findings_and_verification_history(
    report_environment,
):
    client, TestSession = report_environment

    with TestSession() as db:
        application = Application(
            name="Report Test Application",
            base_url="http://127.0.0.1:3000",
            is_active=True,
        )
        db.add(application)
        db.flush()

        create_scan(db, application.id, 1)
        finding = create_finding(db, 1)

        verification_scan = create_scan(db, application.id, 2)
        db.add(
            VerificationAttempt(
                finding_id=finding.id,
                verification_scan_id=verification_scan.id,
                outcome="VERIFIED_RESOLVED",
                evidence="The issue was absent from the verification scan.",
                note="Automated report test.",
                verified_at=datetime.now(UTC),
            )
        )
        db.commit()
        application_id = application.id
        finding_id = finding.id

    response = client.get(f"/reports/applications/{application_id}")

    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    assert response.headers["content-disposition"] == (
        f'attachment; filename="webshield-application-{application_id}-report.json"'
    )

    report = response.json()

    assert report["report_type"] == ("WebShield Application Remediation Report")
    assert report["application"]["id"] == application_id
    assert report["summary"]["total_scans"] == 2
    assert report["summary"]["completed_scans"] == 2
    assert report["summary"]["failed_scans"] == 0
    assert report["summary"]["total_recorded_findings"] == 1
    assert report["summary"]["findings_by_status"] == {"OPEN": 1}
    assert report["summary"]["findings_by_severity"] == {"LOW": 1}
    assert report["summary"]["verification_attempts"] == 1

    finding_record = next(
        item for item in report["findings"] if item["id"] == finding_id
    )
    assert finding_record["verification_history"][0]["outcome"] == ("VERIFIED_RESOLVED")
    assert report["regressions"] == []
    assert len(report["limitations"]) >= 1


def test_report_identifies_regression_after_verified_resolution(
    report_environment,
):
    client, TestSession = report_environment

    with TestSession() as db:
        application = Application(
            name="Regression Report Test",
            base_url="http://127.0.0.1:3000",
            is_active=True,
        )
        db.add(application)
        db.flush()

        create_scan(db, application.id, 1)
        original = create_finding(db, 1)
        original_id = original.id

        verification_scan = create_scan(db, application.id, 2)
        verification_time = verification_scan.started_at + timedelta(minutes=1)

        db.add(
            VerificationAttempt(
                finding_id=original.id,
                verification_scan_id=verification_scan.id,
                outcome="VERIFIED_RESOLVED",
                evidence="No matching finding in verification scan.",
                note="Regression test.",
                verified_at=verification_time,
            )
        )

        # Ensure the later scan starts after the recorded resolution.
        regression_scan = ScanRun(
            id=3,
            application_id=application.id,
            status="COMPLETED",
            scanner="webshield-security-checker",
            started_at=verification_time + timedelta(minutes=1),
            completed_at=verification_time + timedelta(minutes=1),
        )
        db.add(regression_scan)
        db.flush()
        returned = create_finding(db, 3)
        returned_id = returned.id
        db.commit()
        application_id = application.id

    response = client.get(f"/reports/applications/{application_id}")

    assert response.status_code == 200
    report = response.json()

    assert report["summary"]["regression_candidates"] == 1
    assert len(report["regressions"]) == 1
    assert report["regressions"][0]["finding_id"] == returned_id
    assert report["regressions"][0]["title"] == (
        "X-Content-Type-Options Header Missing"
    )
    assert original_id != returned_id


def test_report_returns_404_for_missing_application(
    report_environment,
):
    client, _ = report_environment

    response = client.get("/reports/applications/9999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Application not found"
