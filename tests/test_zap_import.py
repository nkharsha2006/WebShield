from typing import ClassVar

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import (
    Application,
    ScanRun,
    VulnerabilityFinding,
    ZapImportBatch,
)
from app.zap_client import ZapClientError


@pytest.fixture
def zap_environment(monkeypatch):
    """Provide an isolated database and a paginated mock ZAP client."""

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

    class FakeZapClient:
        alerts: ClassVar[list] = []
        version: ClassVar[str] = "2.17.0"
        fail: ClassVar[bool] = False
        calls: ClassVar[list] = []

        def get_version(self):
            if self.fail:
                raise ZapClientError("Mock ZAP connection failure")
            return self.version

        def get_alerts(self, base_url=None, start=0, count=100):
            if self.fail:
                raise ZapClientError("Mock ZAP connection failure")

            assert base_url == "http://127.0.0.1:3000"
            self.calls.append((start, count))
            return self.alerts[start : start + count]

    FakeZapClient.alerts = []
    FakeZapClient.fail = False
    FakeZapClient.version = "2.17.0"
    FakeZapClient.calls = []

    monkeypatch.setattr("app.api.zap.ZapClient", FakeZapClient)

    with TestSession() as db:
        application = Application(
            name="ZAP Import Test",
            base_url="http://127.0.0.1:3000",
            is_active=True,
        )
        db.add(application)
        db.commit()
        application_id = application.id

    try:
        with TestClient(app) as client:
            yield client, TestSession, FakeZapClient, application_id
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def sample_alert(**overrides):
    """Return a sample ZAP alert with optional field overrides."""

    alert = {
        "pluginId": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "url": "http://127.0.0.1:3000/",
        "param": "",
        "risk": "Low",
        "description": "The expected response header is missing.",
        "evidence": "Header was absent.",
        "solution": "Set X-Content-Type-Options: nosniff.",
    }
    alert.update(overrides)
    return alert


def test_import_creates_scan_and_findings(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [
        sample_alert(),
        sample_alert(
            name="Content Security Policy (CSP) Header Not Set",
            pluginId="10038",
            risk="Medium",
        ),
    ]

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["alerts_returned_by_zap"] == 2
    assert result["findings_imported"] == 2
    assert result["alerts_skipped"] == 0
    assert FakeZapClient.calls == [(0, 100)]

    with TestSession() as db:
        scans = db.scalars(select(ScanRun)).all()
        findings = db.scalars(select(VulnerabilityFinding)).all()

        assert len(scans) == 1
        assert scans[0].status == "COMPLETED"
        assert scans[0].scanner == "owasp-zap-alert-import"
        assert len(findings) == 2
        assert {finding.source for finding in findings} == {"owasp-zap"}


def test_import_fetches_all_261_alerts_across_pages(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [
        sample_alert(
            pluginId=str(20000 + index),
            name=f"Sample alert {index}",
            url=f"http://127.0.0.1:3000/item/{index}",
        )
        for index in range(261)
    ]

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["alerts_returned_by_zap"] == 261
    assert result["findings_imported"] == 261
    assert result["alerts_skipped"] == 0
    assert FakeZapClient.calls == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]

    with TestSession() as db:
        assert len(db.scalars(select(ScanRun)).all()) == 1
        assert len(db.scalars(select(VulnerabilityFinding)).all()) == 261


def test_import_stops_after_final_partial_page(zap_environment):
    client, _, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [
        sample_alert(
            pluginId=str(30000 + index),
            name=f"Partial-page alert {index}",
            url=f"http://127.0.0.1:3000/partial/{index}",
        )
        for index in range(201)
    ]

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 200, response.text
    assert response.json()["alerts_returned_by_zap"] == 201
    assert FakeZapClient.calls == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]


def test_import_skips_exact_duplicates_in_one_response(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [
        sample_alert(),
        sample_alert(),
    ]

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 200, response.text
    assert response.json()["findings_imported"] == 1
    assert response.json()["alerts_skipped"] == 1

    with TestSession() as db:
        findings = db.scalars(select(VulnerabilityFinding)).all()
        assert len(findings) == 1


def test_import_preserves_different_affected_urls(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [
        sample_alert(url="http://127.0.0.1:3000/"),
        sample_alert(url="http://127.0.0.1:3000/about"),
    ]

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 200, response.text
    assert response.json()["findings_imported"] == 2

    with TestSession() as db:
        findings = db.scalars(select(VulnerabilityFinding)).all()
        assert {finding.affected_url for finding in findings} == {
            "http://127.0.0.1:3000/",
            "http://127.0.0.1:3000/about",
        }


def test_missing_application_is_rejected(zap_environment):
    client, _, _, _ = zap_environment

    response = client.post("/zap/applications/9999/import-alerts")

    assert response.status_code == 404


def test_inactive_application_is_rejected(zap_environment):
    client, TestSession, _, application_id = zap_environment

    with TestSession() as db:
        application = db.get(Application, application_id)
        application.is_active = False
        db.commit()

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 409


def test_zap_connection_error_returns_502(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.fail = True

    response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert response.status_code == 502

    with TestSession() as db:
        assert db.scalars(select(ScanRun)).all() == []
        assert db.scalars(select(VulnerabilityFinding)).all() == []


def test_severity_mapping():
    from app.api.zap import map_severity

    assert map_severity("Informational") == "INFO"
    assert map_severity("Low") == "LOW"
    assert map_severity("Medium") == "MEDIUM"
    assert map_severity("High") == "HIGH"
    assert map_severity("Critical") == "CRITICAL"
    assert map_severity("Unknown") == "INFO"
    assert map_severity(None) == "INFO"


def test_repeated_import_does_not_duplicate_findings(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [sample_alert()]

    first_response = client.post(f"/zap/applications/{application_id}/import-alerts")
    second_response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.json()["duplicate_import"] is True
    assert second_response.json()["findings_imported"] == 0

    with TestSession() as db:
        scans = db.scalars(select(ScanRun)).all()
        findings = db.scalars(select(VulnerabilityFinding)).all()
        batches = db.scalars(select(ZapImportBatch)).all()

        assert len(scans) == 1
        assert len(findings) == 1
        assert len(batches) == 1


def test_changed_alert_response_creates_new_scan_and_preserves_history(
    zap_environment,
):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = [sample_alert()]

    first_response = client.post(f"/zap/applications/{application_id}/import-alerts")
    assert first_response.status_code == 200

    changed_alert = sample_alert()
    changed_alert["evidence"] = "Different evidence from a later response"
    FakeZapClient.alerts = [changed_alert]

    second_response = client.post(f"/zap/applications/{application_id}/import-alerts")
    assert second_response.status_code == 200

    with TestSession() as db:
        scans = db.scalars(select(ScanRun)).all()
        findings = db.scalars(
            select(VulnerabilityFinding).order_by(VulnerabilityFinding.id)
        ).all()

        assert len(scans) == 2
        assert len(findings) == 2
        assert findings[0].evidence == "Header was absent."
        assert findings[1].evidence == (
            "Different evidence from a later response"
        )
        assert findings[0].status == "OPEN"
        assert findings[1].status == "OPEN"


def test_empty_alert_response_is_imported_once(zap_environment):
    client, TestSession, FakeZapClient, application_id = zap_environment
    FakeZapClient.alerts = []

    first_response = client.post(f"/zap/applications/{application_id}/import-alerts")
    second_response = client.post(f"/zap/applications/{application_id}/import-alerts")

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.json()["duplicate_import"] is True

    with TestSession() as db:
        assert len(db.scalars(select(ScanRun)).all()) == 1
        assert db.scalars(select(VulnerabilityFinding)).all() == []
