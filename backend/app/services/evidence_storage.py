
from sqlalchemy.orm import Session

from backend.app.models.evidence import EvidenceRecord
from backend.app.models.evidence_db import EvidenceDB
from backend.app.core.integrity import calculate_sha256


def save_evidence(
    db: Session,
    evidence: EvidenceRecord
) -> EvidenceDB:

    evidence_hash = calculate_sha256(evidence)

    record_data = evidence.model_dump(mode="json")

    db_record = EvidenceDB(
        **record_data,
        sha256_hash=evidence_hash
    )

    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return db_record


def get_evidence(
    db: Session,
    evidence_id: str
):
    return db.query(EvidenceDB).filter(
        EvidenceDB.evidence_id == evidence_id
    ).first()


def list_evidence(
    db: Session,
    limit: int = 100,
    offset: int = 0
):
    return (
        db.query(EvidenceDB)
        .order_by(EvidenceDB.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def verify_stored_evidence(
    db: Session,
    evidence_id: str
) -> bool:

    stored_record = get_evidence(db, evidence_id)

    if stored_record is None:
        return False

    evidence_data = {
        column.name: getattr(stored_record, column.name)
        for column in EvidenceDB.__table__.columns
        if column.name != "sha256_hash"
    }

    evidence = EvidenceRecord.model_validate(evidence_data)

    current_hash = calculate_sha256(evidence)

    return current_hash == stored_record.sha256_hash
