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
TARGET_URL = "http://127.0.0.1:3000/"
TITLE = "X-Content-Type-Options Header Missing"


@pytest.fixture
def environment():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(bind=engine, autoflush=False)
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


def seed_data(TestSession):
    now = datetime.now(UTC)

    with TestSession() as db:
        app_record = Application(
            name="Verification Test App",
            base_url=TARGET_URL,
            is_active=True,
        )
        db.add(app_record)
        db.flush()

        original_scan = ScanRun(
            id=1,
            application_id=app_record.id,
            status="COMPLETED",
            scanner=CHECKER,
            started_at=now - timedelta(minutes=3),
            completed_at=now - timedelta(minutes=2),
        )
        db.add(original_scan)

        original_finding = VulnerabilityFinding(
            scan_id=1,
            title=TITLE,
            severity="LOW",
            affected_url=TARGET_URL,
            description="Security header is missing.",
            evidence="Header absent.",
            remediation="Add X-Content-Type-Options: nosniff.",
            status="OPEN",
            source=CHECKER,
        )
        db.add(original_finding)

        # Scan 2 is completed and contains no matching finding.
        clean_scan = ScanRun(
            id=2,
            application_id=app_record.id,
            status="COMPLETED",
            scanner=CHECKER,
            started_at=now - timedelta(minutes=1),
            completed_at=now - timedelta(seconds=30),
        )
        db.add(clean_scan)

        # Scan 3 exists but is not completed.
        incomplete_scan = ScanRun(
            id=3,
            application_id=app_record.id,
            status="RUNNING",
            scanner=CHECKER,
            started_at=now,
            completed_at=None,
        )
        db.add(incomplete_scan)

        # Scan 4 belongs to another application.
        other_app = Application(
            name="Other Test App",
            base_url="http://127.0.0.1:4000/",
            is_active=True,
        )
        db.add(other_app)
        db.flush()

        wrong_app_scan = ScanRun(
            id=4,
            application_id=other_app.id,
            status="COMPLETED",
            scanner=CHECKER,
            started_at=now,
            completed_at=now + timedelta(seconds=1),
        )
        db.add(wrong_app_scan)

        db.commit()
        return original_finding.id


def verify_payload(scan_id):
    return {
        "verification_scan_id": scan_id,
        "outcome": "INCONCLUSIVE",
        "evidence": "Automated verification safeguard test.",
        "note": "Testing verification validation.",
    }


def test_missing_verification_scan_is_rejected(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    response = client.post(
        f"/findings/{finding_id}/verify",
        json=verify_payload(999),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Verification scan not found"


def test_incomplete_verification_scan_is_rejected(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    response = client.post(
        f"/findings/{finding_id}/verify",
        json=verify_payload(3),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("Verification scan must be COMPLETED.")


def test_verification_scan_from_another_application_is_rejected(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    response = client.post(
        f"/findings/{finding_id}/verify",
        json=verify_payload(4),
    )

    assert response.status_code == 400
    assert "same application" in response.json()["detail"]


def test_direct_verified_resolved_status_is_rejected(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    response = client.patch(
        f"/findings/{finding_id}/status",
        json={"status": "VERIFIED_RESOLVED"},
    )

    assert response.status_code == 409
    assert "remediation verification" in response.json()["detail"]


def test_verification_history_is_retrievable(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    # Scan 2 has no matching finding, so resolution should be verified.
    verify_response = client.post(
        f"/findings/{finding_id}/verify",
        json=verify_payload(2),
    )
    assert verify_response.status_code == 201, verify_response.text
    assert verify_response.json()["outcome"] == "VERIFIED_RESOLVED"

    history_response = client.get(f"/findings/{finding_id}/verifications")

    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) == 1
    assert history[0]["finding_id"] == finding_id
    assert history[0]["verification_scan_id"] == 2
    assert history[0]["outcome"] == "VERIFIED_RESOLVED"


def test_vulnerability_still_present_keeps_finding_open(environment):
    client, TestSession = environment
    finding_id = seed_data(TestSession)

    # Add the same vulnerability to completed verification scan 2.
    with TestSession() as db:
        existing = VulnerabilityFinding(
            scan_id=2,
            title=TITLE,
            severity="LOW",
            affected_url=TARGET_URL,
            description="The security header is still missing.",
            evidence="Header remains absent.",
            remediation="Add X-Content-Type-Options: nosniff.",
            status="OPEN",
            source=CHECKER,
        )
        db.add(existing)
        db.commit()

    response = client.post(
        f"/findings/{finding_id}/verify",
        json=verify_payload(2),
    )

    assert response.status_code == 201, response.text
    result = response.json()

    # The API should determine the outcome from the scan findings.
    assert result["outcome"] == "STILL_PRESENT"
    assert result["finding_id"] == finding_id
    assert result["verification_scan_id"] == 2
    assert "detected the same issue" in result["evidence"]

    # The original finding must remain open.
    finding_response = client.get(f"/findings/{finding_id}")
    assert finding_response.status_code == 200
    assert finding_response.json()["status"] == "OPEN"

    # The verification history should contain this attempt.
    history_response = client.get(f"/findings/{finding_id}/verifications")
    assert history_response.status_code == 200
    history = history_response.json()

    assert len(history) == 1
    assert history[0]["outcome"] == "STILL_PRESENT"
