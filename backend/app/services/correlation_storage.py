from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.models.correlation import EvidenceCorrelation
from backend.app.models.correlation_db import EvidenceCorrelationDB
from backend.app.models.evidence_db import EvidenceDB


def save_correlation(
    db: Session,
    correlation: EvidenceCorrelation,
):
    evidence = db.query(EvidenceDB).filter(
        EvidenceDB.evidence_id == correlation.evidence_id
    ).first()

    if evidence is None:
        raise ValueError("Evidence record does not exist")

    if correlation.parent_event_id:
        parent = db.query(EvidenceDB).filter(
            EvidenceDB.evidence_id == correlation.parent_event_id
        ).first()

        if parent is None:
            raise ValueError("Parent evidence record does not exist")

        if parent.evidence_id == correlation.evidence_id:
            raise ValueError("Evidence cannot be its own parent")

    existing = db.query(EvidenceCorrelationDB).filter(
        EvidenceCorrelationDB.evidence_id == correlation.evidence_id
    ).first()

    if existing:
        existing.correlation_id = correlation.correlation_id
        existing.session_id = correlation.session_id
        existing.agent_id = correlation.agent_id
        existing.parent_event_id = correlation.parent_event_id
        return db.commit()

    record = EvidenceCorrelationDB(
        evidence_id=correlation.evidence_id,
        correlation_id=correlation.correlation_id,
        session_id=correlation.session_id,
        agent_id=correlation.agent_id,
        parent_event_id=correlation.parent_event_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return record


def get_correlation(
    db: Session,
    evidence_id: str,
):
    return db.query(EvidenceCorrelationDB).filter(
        EvidenceCorrelationDB.evidence_id == evidence_id
    ).first()


def get_all_correlations(db: Session):
    return db.query(EvidenceCorrelationDB).all()