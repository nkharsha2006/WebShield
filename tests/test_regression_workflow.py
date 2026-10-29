from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import Application, ScanRun, VulnerabilityFinding

CHECKER = "webshield-security-checker"
FINDING_TITLE = "X-Content-Type-Options Header Missing"
TARGET_URL = "http://127.0.0.1:3000/"


@pytest.fixture
def test_environment():
    """Use an isolated in-memory database for this test."""
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
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def add_scan(db, application_id, scan_id, started_at):
    scan = ScanRun(
        id=scan_id,
        application_id=application_id,
        status="COMPLETED",
        scanner=CHECKER,
        started_at=started_at,
        completed_at=started_at + timedelta(seconds=1),
    )
    db.add(scan)
    db.flush()
    return scan


def add_finding(db, scan_id):
    finding = VulnerabilityFinding(
        scan_id=scan_id,
        title=FINDING_TITLE,
        severity="LOW",
        affected_url=TARGET_URL,
        description="The response does not include X-Content-Type-Options.",
        evidence="Header missing from the HTTP response.",
        remediation="Configure X-Content-Type-Options: nosniff.",
        status="OPEN",
        source=CHECKER,
    )
    db.add(finding)
    db.flush()
    return finding


def test_resolution_then_regression_reopens_original_finding(
    test_environment,
):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    # Create the application, original finding, and a clean verification scan.
    with TestSession() as db:
        application = Application(
            name="WebShield Regression Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()

        add_scan(db, application.id, 1, baseline)
        original = add_finding(db, 1)
        original_finding_id = original.id

        add_scan(db, application.id, 2, baseline + timedelta(minutes=1))
        db.commit()

    # Verify that the issue is absent from scan 2.
    verification_response = client.post(
        f"/findings/{original_finding_id}/verify",
        json={
            "verification_scan_id": 2,
            "outcome": "INCONCLUSIVE",
            "evidence": "Check whether the fix is detected.",
            "note": "Automated regression workflow test.",
        },
    )

    assert verification_response.status_code == 201, (
        verification_response.status_code,
        verification_response.text,
    )
    verification = verification_response.json()
    assert verification["outcome"] == "VERIFIED_RESOLVED"
    assert verification["verification_scan_id"] == 2

    # Simulate a later scan where the same issue has returned.
    with TestSession() as db:
        application = db.query(Application).filter_by(id=1).one()

        add_scan(
            db,
            application.id,
            3,
            datetime.now(UTC) + timedelta(seconds=2),
        )
        returned_finding = add_finding(db, 3)
        returned_finding_id = returned_finding.id
        db.commit()

    # Compare the returning issue with the clean scan.
    comparison_response = client.get(
        "/findings/compare/3",
        params={"previous_scan_id": 2},
    )

    assert comparison_response.status_code == 200, (
        comparison_response.status_code,
        comparison_response.text,
    )
    comparison = comparison_response.json()

    # Match the actual API response structure.
    assert comparison["summary"]["regressions"] == 1
    assert comparison["summary"]["new"] == 0
    assert comparison["regressions"][0]["title"] == FINDING_TITLE
    assert original_finding_id in comparison["reopened_original_finding_ids"]

    # The original finding should have been reopened.
    original_response = client.get(f"/findings/{original_finding_id}")
    assert original_response.status_code == 200
    assert original_response.json()["status"] == "OPEN"

    # The dashboard should report the returning issue.
    dashboard_response = client.get("/dashboard/data")
    assert dashboard_response.status_code == 200

    dashboard = dashboard_response.json()
    assert dashboard["summary"]["regression_candidates"] >= 1

    dashboard_regressions = dashboard.get("regressions", [])
    assert any(
        item.get("finding_id") == returned_finding_id
        and item.get("title") == FINDING_TITLE
        for item in dashboard_regressions
    )


def test_finding_present_in_both_scans_is_recurring(test_environment):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    # Create one application and two completed scans.
    with TestSession() as db:
        application = Application(
            name="WebShield Recurring Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()

        application_id = application.id

        add_scan(db, application_id, 1, baseline)
        add_finding(db, 1)

        add_scan(
            db,
            application_id,
            2,
            baseline + timedelta(minutes=1),
        )
        add_finding(db, 2)

        db.commit()

    # Compare scan 2 against scan 1.
    response = client.get(
        "/findings/compare/2",
        params={"previous_scan_id": 1},
    )

    assert response.status_code == 200, (
        response.status_code,
        response.text,
    )

    result = response.json()

    # The same issue should be recurring, not new or a regression.
    assert result["summary"]["new"] == 0
    assert result["summary"]["recurring"] == 1
    assert result["summary"]["regressions"] == 0
    assert result["summary"]["resolved_candidates"] == 0

    assert len(result["recurring_findings"]) == 1
    assert result["recurring_findings"][0]["title"] == FINDING_TITLE


def test_scan_comparison_normalizes_case_and_trailing_slashes(
    test_environment,
):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    with TestSession() as db:
        application = Application(
            name="WebShield Normalization Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()
        application_id = application.id

        # Previous scan: original capitalization and trailing slash.
        add_scan(db, application_id, 1, baseline)
        add_finding(db, 1)

        # Latest scan: equivalent issue with different formatting.
        add_scan(
            db,
            application_id,
            2,
            baseline + timedelta(minutes=1),
        )
        latest_finding = add_finding(db, 2)
        latest_finding.title = "x-content-type-options header missing"
        latest_finding.affected_url = "http://127.0.0.1:3000"
        latest_finding.source = "WEBSHIELD-SECURITY-CHECKER"

        db.commit()

    response = client.get(
        "/findings/compare/2",
        params={"previous_scan_id": 1},
    )

    assert response.status_code == 200, (
        response.status_code,
        response.text,
    )

    result = response.json()

    assert result["summary"]["new"] == 0
    assert result["summary"]["recurring"] == 1
    assert result["summary"]["regressions"] == 0
    assert result["summary"]["resolved_candidates"] == 0
    assert len(result["recurring_findings"]) == 1


def test_scan_comparison_rejects_different_applications(test_environment):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    with TestSession() as db:
        first_app = Application(
            name="WebShield Application A",
            base_url=TARGET_URL,
            is_active=True,
        )
        second_app = Application(
            name="WebShield Application B",
            base_url="http://127.0.0.1:3001/",
            is_active=True,
        )
        db.add_all([first_app, second_app])
        db.flush()

        add_scan(db, first_app.id, 1, baseline)
        add_finding(db, 1)

        add_scan(
            db,
            second_app.id,
            2,
            baseline + timedelta(minutes=1),
        )
        db.commit()

    response = client.get(
        "/findings/compare/2",
        params={"previous_scan_id": 1},
    )

    assert response.status_code == 400
    assert "same application" in response.json()["detail"]


def test_scan_comparison_rejects_different_scanners(test_environment):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    with TestSession() as db:
        application = Application(
            name="WebShield Scanner Isolation Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()

        # Both scans belong to the same application.
        add_scan(db, application.id, 1, baseline)
        add_finding(db, 1)

        # The second scan uses a different scanner.
        second_scan = add_scan(
            db,
            application.id,
            2,
            baseline + timedelta(minutes=1),
        )
        second_scan.scanner = "another-security-scanner"

        db.commit()

    response = client.get(
        "/findings/compare/2",
        params={"previous_scan_id": 1},
    )

    assert response.status_code == 400
    assert "same scanner" in response.json()["detail"]


def test_scan_comparison_rejects_missing_previous_scan(test_environment):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    with TestSession() as db:
        application = Application(
            name="WebShield Missing Scan Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()

        add_scan(db, application.id, 2, baseline)
        db.commit()

    response = client.get(
        "/findings/compare/2",
        params={"previous_scan_id": 999},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == ("No eligible previous scan was found.")


def test_scan_comparison_rejects_incomplete_previous_scan(test_environment):
    client, TestSession = test_environment
    baseline = datetime.now(UTC) - timedelta(minutes=5)

    with TestSession() as db:
        application = Application(
            name="WebShield Incomplete Scan Test",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(application)
        db.flush()

        add_scan(db, application.id, 1, baseline)

        incomplete_scan = ScanRun(
            id=2,
            application_id=application.id,
            status="RUNNING",
            scanner=CHECKER,
            started_at=baseline + timedelta(minutes=1),
            completed_at=None,
        )
        db.add(incomplete_scan)
        db.commit()

    response = client.get(
        "/findings/compare/1",
        params={"previous_scan_id": 2},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("The previous scan must be COMPLETED.")
