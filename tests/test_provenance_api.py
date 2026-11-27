
import pytest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.core.database import Base, get_db
from backend.app.core.provenance_signing import generate_provenance_key_pair
from backend.app.models.evidence import EvidenceRecord
from backend.app.models.source_db import EvidenceProvenanceDB
from backend.app.services.evidence_storage import save_evidence


@pytest.fixture
def test_environment():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    TestingSession = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, TestingSession

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def register_test_source(client):
    response = client.post(
        "/sources/",
        json={
            "source_id": str(uuid4()),
            "name": "Test Evidence Source",
            "source_type": "ENDPOINT",
            "owner": "Test Owner",
            "trust_level": "LIMITED",
            "description": "Test source for provenance API"
        }
    )

    assert response.status_code in (200, 201), response.text

    return response.json()["source_id"]


def create_test_evidence(session_factory):
    evidence = EvidenceRecord(
        identity="test-user",
        principal_type="USER",
        action="LOGIN",
        resource="test-system",
        authorization_status="AUTHORIZED",
        execution_status="SUCCESS",
        observed_effect="Test login completed",
        source="test-source"
    )

    with session_factory() as db:
        saved_evidence = save_evidence(db, evidence)

        # EvidenceDB uses evidence_id as its primary key.
        return str(saved_evidence.evidence_id)


def register_test_provenance(client, source_id, evidence_id):
    response = client.post(
        f"/sources/{source_id}/provenance",
        json={
            "evidence_id": evidence_id,
            "collector_identity": "Test-Collector",
            "collection_method": "Automated test collection",
            "collected_at": "2026-01-01T10:00:00+00:00",
            "transfer_details": "Test transfer"
        }
    )

    assert response.status_code in (200, 201), response.text

    return response


def test_provenance_is_automatically_signed(test_environment):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    response = register_test_provenance(
        client,
        source_id,
        evidence_id
    )

    data = response.json()

    assert data["signature_algorithm"] == "Ed25519"
    assert data["signature_status"] == "SIGNED"
    assert data.get("signature")

    with session_factory() as db:
        record = db.query(EvidenceProvenanceDB).filter_by(
            provenance_id=data["provenance_id"]
        ).first()

        assert record is not None
        assert record.signature is not None
        assert record.public_key is not None


def test_valid_provenance_signature_verifies(test_environment):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    registration = register_test_provenance(
        client,
        source_id,
        evidence_id
    )

    provenance_id = registration.json()["provenance_id"]

    response = client.get(
        f"/sources/{source_id}/provenance/"
        f"{provenance_id}/verify"
    )

    assert response.status_code == 200
    assert response.json()["signature_status"] == "VERIFIED"


def test_modified_provenance_metadata_is_detected(test_environment):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    registration = register_test_provenance(
        client,
        source_id,
        evidence_id
    )

    provenance_id = registration.json()["provenance_id"]

    with session_factory() as db:
        record = db.query(EvidenceProvenanceDB).filter_by(
            provenance_id=provenance_id
        ).first()

        assert record is not None

        record.collector_identity = "Modified-Collector"
        db.commit()

    response = client.get(
        f"/sources/{source_id}/provenance/"
        f"{provenance_id}/verify"
    )

    assert response.status_code == 200
    assert response.json()["signature_status"] == "SIGNATURE_INVALID"


def test_replaced_public_key_is_detected(test_environment):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    registration = register_test_provenance(
        client,
        source_id,
        evidence_id
    )

    provenance_id = registration.json()["provenance_id"]

    _, replacement_public_key = generate_provenance_key_pair()

    with session_factory() as db:
        record = db.query(EvidenceProvenanceDB).filter_by(
            provenance_id=provenance_id
        ).first()

        assert record is not None

        record.public_key = replacement_public_key
        db.commit()

    response = client.get(
        f"/sources/{source_id}/provenance/"
        f"{provenance_id}/verify"
    )

    assert response.status_code == 200
    assert response.json()["signature_status"] == "SIGNATURE_INVALID"


def test_legacy_unsigned_provenance_returns_not_signed(
    test_environment
):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    evidence_id = create_test_evidence(session_factory)

    provenance_id = str(uuid4())

    record = EvidenceProvenanceDB(
        provenance_id=provenance_id,
        evidence_id=evidence_id,
        source_id=source_id,
        collector_identity="Legacy-Test-Collector",
        collection_method="Legacy test collection",
        collected_at="2026-01-01T10:00:00+00:00",
        transfer_details="Legacy unsigned record",
        signature=None,
        public_key=None,
        signature_algorithm="Ed25519"
    )

    with session_factory() as db:
        db.add(record)
        db.commit()

    response = client.get(
        f"/sources/{source_id}/provenance/"
        f"{provenance_id}/verify"
    )

    assert response.status_code == 200
    assert response.json()["signature_status"] == "NOT_SIGNED"


def test_missing_provenance_returns_404(test_environment):
    client, session_factory = test_environment

    source_id = register_test_source(client)
    missing_provenance_id = str(uuid4())

    response = client.get(
        f"/sources/{source_id}/provenance/"
        f"{missing_provenance_id}/verify"
    )

    assert response.status_code == 404
