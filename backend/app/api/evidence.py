
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.evidence import EvidenceRecord
from backend.app.services.evidence_storage import (
    save_evidence,
    get_evidence,
    verify_stored_evidence,
    list_evidence
)


router = APIRouter(
    prefix="/evidence",
    tags=["Evidence Verification"]
)


class EvidenceSubmissionResponse(BaseModel):
    evidence: EvidenceRecord
    sha256_hash: str


# 1. Submit new evidence
@router.post("/", response_model=EvidenceSubmissionResponse)
def submit_evidence(
    evidence: EvidenceRecord,
    db: Session = Depends(get_db)
):
    saved = save_evidence(db, evidence)

    return {
        "evidence": evidence,
        "sha256_hash": saved.sha256_hash
    }


# 2. Retrieve all evidence records
@router.get("/")
def retrieve_all_evidence(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    records = list_evidence(
        db=db,
        limit=limit,
        offset=offset
    )

    return {
        "total": len(records),
        "records": [
            {
                "evidence": {
                    column.name: getattr(record, column.name)
                    for column in record.__table__.columns
                    if column.name != "sha256_hash"
                },
                "sha256_hash": record.sha256_hash
            }
            for record in records
        ]
    }


# 3. Retrieve one evidence record
@router.get("/{evidence_id}")
def retrieve_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    record = get_evidence(db, evidence_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence record not found"
        )

    return {
        "evidence": {
            column.name: getattr(record, column.name)
            for column in record.__table__.columns
            if column.name != "sha256_hash"
        },
        "sha256_hash": record.sha256_hash
    }


# 4. Verify evidence integrity
@router.get("/{evidence_id}/verify")
def verify_evidence(
    evidence_id: str,
    db: Session = Depends(get_db)
):
    record = get_evidence(db, evidence_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence record not found"
        )

    valid = verify_stored_evidence(db, evidence_id)

    return {
        "evidence_id": evidence_id,
        "integrity_valid": valid,
        "status": "VERIFIED" if valid else "INTEGRITY_FAILURE"
    }
