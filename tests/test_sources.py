
import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.core.database import Base, get_db
from backend.app.models.evidence import EvidenceRecord
from backend.app.services.evidence_storage import save_evidence


@pytest.fixture
def test_environment():

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False
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


def register_test_source(client):

    response = client.post(
        "/sources/",
        json={
            "name": "Test Windows Event Log",
            "source_type": "ENDPOINT_LOG",
            "owner": "AEGIS-X Lab",
            "description": "Synthetic test evidence source"
        }
    )

    assert response.status_code == 200

    return response.json()["source_id"]


def create_test_evidence(session_factory):

    evidence = EvidenceRecord(
        identity="test-user-001",
        principal_type="human",
        action="Login attempt",
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Synthetic test event",
        source="synthetic-lab"
    )

    with session_factory() as db:
        save_evidence(db, evidence)

    return evidence.evidence_id


def test_source_registration(test_environment):

    client, _ = test_environment

    response = client.post(
        "/sources/",
        json={
            "name": "Windows Security Event Log",
            "source_type": "ENDPOINT_LOG",
            "owner": "AEGIS-X Lab",
            "description": "Windows security monitoring"
        }
    )

    assert response.status_code == 200

    result = response.json()

    assert result["name"] == "Windows Security Event Log"
    assert result["trust_level"] == "UNVERIFIED"
    assert result["status"] == "ACTIVE"
    assert result["source_id"]


def test_default_source_trust(test_environment):

    client, _ = test_environment

    source_id = register_test_source(client)

    response = client.get(f"/sources/{source_id}")

    assert response.status_code == 200
    assert response.json()["trust_level"] == "UNVERIFIED"


def test_source_trust_update(test_environment):

    client, _ = test_environment

    source_id = register_test_source(client)

    response = client.patch(
        f"/sources/{source_id}/trust",
        json={"trust_level": "LIMITED"}
    )

    assert response.status_code == 200
    assert response.json()["trust_level"] == "LIMITED"
    assert response.json()["status"] == "ACTIVE"


def test_invalid_source_trust_level(test_environment):

    client, _ = test_environment

    source_id = register_test_source(client)

    response = client.patch(
        f"/sources/{source_id}/trust",
        json={"trust_level": "UNKNOWN_LEVEL"}
    )

    assert response.status_code == 422


def test_source_revocation(test_environment):

    client, _ = test_environment

    source_id = register_test_source(client)

    response = client.post(
        f"/sources/{source_id}/revoke"
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REVOKED"
    assert response.json()["trust_level"] == "UNVERIFIED"


def test_provenance_registration_and_retrieval(test_environment):

    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    response = client.post(
        f"/sources/{source_id}/provenance",
        json={
            "evidence_id": evidence_id,
            "collector_identity": "AEGIS-X-Test-Collector",
            "collection_method": "Synthetic test collection",
            "transfer_details": "Isolated test environment"
        }
    )

    assert response.status_code == 200

    result = response.json()

    assert result["evidence_id"] == evidence_id
    assert result["source_id"] == source_id
    assert result["source_trust_level"] == "UNVERIFIED"
    assert result["provenance_id"]

    history = client.get(
        f"/sources/{source_id}/provenance"
    )

    assert history.status_code == 200

    history_result = history.json()

    assert history_result["total_records"] == 1
    assert history_result["provenance"][0]["evidence_id"] == evidence_id


def test_revoked_source_cannot_register_provenance(test_environment):

    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    client.post(f"/sources/{source_id}/revoke")

    response = client.post(
        f"/sources/{source_id}/provenance",
        json={
            "evidence_id": evidence_id,
            "collector_identity": "AEGIS-X-Test-Collector",
            "collection_method": "Synthetic test collection"
        }
    )

    assert response.status_code == 409


def test_missing_evidence_rejected(test_environment):

    client, _ = test_environment

    source_id = register_test_source(client)

    response = client.post(
        f"/sources/{source_id}/provenance",
        json={
            "evidence_id": "00000000-0000-0000-0000-000000000000",
            "collector_identity": "AEGIS-X-Test-Collector",
            "collection_method": "Synthetic test collection"
        }
    )

    assert response.status_code == 404


def test_missing_source_rejected(test_environment):

    client, session_factory = test_environment

    evidence_id = create_test_evidence(session_factory)

    response = client.post(
        "/sources/00000000-0000-0000-0000-000000000000/provenance",
        json={
            "evidence_id": evidence_id,
            "collector_identity": "AEGIS-X-Test-Collector",
            "collection_method": "Synthetic test collection"
        }
    )

    assert response.status_code == 404


def test_revoked_source_cannot_be_reactivated_through_trust_update(
    test_environment
):

    client, _ = test_environment

    source_id = register_test_source(client)

    client.post(f"/sources/{source_id}/revoke")

    response = client.patch(
        f"/sources/{source_id}/trust",
        json={"trust_level": "TRUSTED"}
    )

    assert response.status_code == 409
