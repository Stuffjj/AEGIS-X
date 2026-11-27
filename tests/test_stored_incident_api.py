
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.core.database import Base, get_db
from backend.app.models.evidence_db import EvidenceDB
from backend.app.models.incident_db import (
    IncidentDB,
    IncidentEvidenceDB,
)
from backend.app.models.evidence import EvidenceRecord
from backend.app.services.evidence_storage import save_evidence


@pytest.fixture
def test_environment():
    """
    Use an isolated in-memory SQLite database.
    Never modify the project's real database.
    """

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            yield client, TestingSession
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def create_test_incident(client, title="Test incident"):
    response = client.post(
        "/incidents/",
        json={"title": title},
    )

    assert response.status_code == 200
    return response.json()["incident_id"]


def create_test_evidence():
    return EvidenceRecord(
        evidence_id=str(uuid4()),
        identity="test-user-001",
        principal_type="human",
        action="Login attempt",
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Test session created",
        source="synthetic-lab",
        timestamp=datetime.now(timezone.utc),
    )


def save_and_link_evidence(
    client,
    session_factory,
    incident_id,
    evidence,
):
    with session_factory() as db:
        save_evidence(db, evidence)

    response = client.post(
        f"/incidents/{incident_id}/evidence/{evidence.evidence_id}"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "LINKED"


def test_stored_incident_valid_evidence(test_environment):
    client, session_factory = test_environment

    incident_id = create_test_incident(client)
    evidence = create_test_evidence()

    save_and_link_evidence(
        client, session_factory, incident_id, evidence
    )

    response = client.post(
        f"/incidents/{incident_id}/reconstruct"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["report_type"] == "STORED_INCIDENT_RECONSTRUCTION"
    assert result["total_events"] == 1
    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"
    assert result["timeline"][0]["integrity_valid"] is True
    assert result["timeline"][0]["integrity_status"] == "INTEGRITY_VALID"
    assert result["findings"] == []


def test_stored_incident_tampered_evidence(test_environment):
    client, session_factory = test_environment

    incident_id = create_test_incident(client)
    evidence = create_test_evidence()

    save_and_link_evidence(
        client, session_factory, incident_id, evidence
    )

    # Simulate tampering in the isolated test database.
    # Preserve the original SHA-256 hash.
    with session_factory() as db:
        stored = db.get(EvidenceDB, evidence.evidence_id)
        stored.action = "Unauthorized file access"
        db.commit()

    response = client.post(
        f"/incidents/{incident_id}/reconstruct"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert result["timeline"][0]["integrity_valid"] is False
    assert result["timeline"][0]["integrity_status"] == "INTEGRITY_FAILURE"

    integrity_findings = [
        finding
        for finding in result["findings"]
        if finding["finding"] == "EVIDENCE_INTEGRITY_FAILURE"
    ]

    assert len(integrity_findings) == 1
    assert integrity_findings[0]["severity"] == "HIGH"
    assert integrity_findings[0]["evidence_id"] == evidence.evidence_id


def test_stored_incident_multiple_integrity_failures(test_environment):
    client, session_factory = test_environment

    incident_id = create_test_incident(client)

    first = create_test_evidence()
    second = create_test_evidence()
    second.action = "Permission check"

    for evidence in [first, second]:
        save_and_link_evidence(
            client, session_factory, incident_id, evidence
        )

    with session_factory() as db:
        for evidence in [first, second]:
            stored = db.get(EvidenceDB, evidence.evidence_id)
            stored.action = "Modified after storage"

        db.commit()

    response = client.post(
        f"/incidents/{incident_id}/reconstruct"
    )

    assert response.status_code == 200

    result = response.json()

    integrity_findings = [
        finding
        for finding in result["findings"]
        if finding["finding"] == "EVIDENCE_INTEGRITY_FAILURE"
    ]

    assert result["total_events"] == 2
    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert len(integrity_findings) == 2


def test_stored_incident_missing_incident(test_environment):
    client, _ = test_environment

    response = client.post(
        f"/incidents/{uuid4()}/reconstruct"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_stored_incident_empty_evidence(test_environment):
    client, _ = test_environment

    incident_id = create_test_incident(client)

    response = client.post(
        f"/incidents/{incident_id}/reconstruct"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["total_events"] == 0
    assert result["timeline"] == []
    assert result["status"] == "NO_EVIDENCE"
