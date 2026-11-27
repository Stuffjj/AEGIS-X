
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base
from backend.app.models.evidence import EvidenceRecord
from backend.app.models.evidence_db import EvidenceDB
from backend.app.services.evidence_storage import (
    save_evidence,
    get_evidence,
    verify_stored_evidence
)


def test_evidence_database_storage():

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(bind=engine)

    with TestSession() as db:

        evidence = EvidenceRecord(
            identity="test-user-001",
            principal_type="human",
            action="Login attempt",
            resource="Test application",
            authorization_status="authorized",
            execution_status="success",
            observed_effect="Test session created",
            source="synthetic-lab"
        )

        saved = save_evidence(db, evidence)

        retrieved = get_evidence(db, saved.evidence_id)

        assert retrieved is not None
        assert retrieved.identity == "test-user-001"
        assert retrieved.sha256_hash is not None

        assert verify_stored_evidence(
            db, saved.evidence_id
        ) is True

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
