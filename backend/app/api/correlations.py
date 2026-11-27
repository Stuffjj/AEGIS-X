from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.correlation import EvidenceCorrelation
from backend.app.services.correlation_storage import (
    save_correlation,
    get_correlation,
    get_all_correlations,
)

router = APIRouter(
    prefix="/correlations",
    tags=["Evidence Correlation"],
)


@router.post("/")
def create_correlation(
    correlation: EvidenceCorrelation,
    db: Session = Depends(get_db),
):
    try:
        result = save_correlation(db, correlation)
        return {
            "status": "SUCCESS",
            "message": "Correlation metadata saved successfully",
            "evidence_id": correlation.evidence_id,
            "correlation_id": correlation.correlation_id,
            "session_id": correlation.session_id,
            "agent_id": correlation.agent_id,
            "parent_event_id": correlation.parent_event_id,
        }

    except ValueError as error:
        db.rollback()
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


@router.get("/")
def list_correlations(
    db: Session = Depends(get_db),
):
    records = get_all_correlations(db)

    return {
        "total": len(records),
        "correlations": [
            {
                "evidence_id": item.evidence_id,
                "correlation_id": item.correlation_id,
                "session_id": item.session_id,
                "agent_id": item.agent_id,
                "parent_event_id": item.parent_event_id,
                "created_at": item.created_at,
            }
            for item in records
        ],
    }


@router.get("/{evidence_id}")
def read_correlation(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    result = get_correlation(db, evidence_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Correlation metadata not found",
        )

    return {
        "evidence_id": result.evidence_id,
        "correlation_id": result.correlation_id,
        "session_id": result.session_id,
        "agent_id": result.agent_id,
        "parent_event_id": result.parent_event_id,
        "created_at": result.created_at,
    }