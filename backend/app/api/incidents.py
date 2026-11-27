
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

from backend.app.models.evidence import EvidenceRecord
from backend.app.models.evidence_db import EvidenceDB
from backend.app.models.incident_db import (
    IncidentDB,
    IncidentEvidenceDB
)

from backend.app.services.evidence_storage import (
    verify_stored_evidence
)

from backend.app.services.incident_reconstruction import (
    reconstruct_incident
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incident Reconstruction"]
)


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class IncidentReconstructionRequest(BaseModel):
    records: list[EvidenceRecord] = Field(
        description="Evidence records belonging to one investigation"
    )


class CreateIncidentRequest(BaseModel):
    title: str = Field(
        default="Security Investigation",
        min_length=1,
        max_length=200
    )

    session_id: str | None = Field(
        default=None,
        max_length=100
    )


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def get_incident_or_404(
    incident_id: str,
    db: Session
):
    incident = db.get(
        IncidentDB,
        incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident


def convert_database_evidence(
    database_record: EvidenceDB
) -> EvidenceRecord:

    timestamp_value = database_record.timestamp

    # Python 3.10 compatibility for UTC timestamps.
    if timestamp_value.endswith("Z"):
        timestamp_value = (
            timestamp_value[:-1] + "+00:00"
        )

    parsed_timestamp = datetime.fromisoformat(
        timestamp_value
    )

    return EvidenceRecord(
        evidence_id=database_record.evidence_id,
        identity=database_record.identity,
        principal_type=database_record.principal_type,
        action=database_record.action,
        resource=database_record.resource,
        authorization_status=database_record.authorization_status,
        execution_status=database_record.execution_status,
        observed_effect=database_record.observed_effect,
        source=database_record.source,
        timestamp=parsed_timestamp
    )


def get_incident_records(
    incident_id: str,
    db: Session
):
    links = (
        db.query(IncidentEvidenceDB)
        .filter(
            IncidentEvidenceDB.incident_id == incident_id
        )
        .order_by(
            IncidentEvidenceDB.linked_at.asc()
        )
        .all()
    )

    records = []

    for link in links:

        evidence = db.get(
            EvidenceDB,
            link.evidence_id
        )

        if evidence is not None:
            records.append(
                convert_database_evidence(evidence)
            )

    return records


# --------------------------------------------------
# RECONSTRUCT SUPPLIED EVIDENCE
# --------------------------------------------------

@router.post("/reconstruct")
def reconstruct_incident_api(
    request: IncidentReconstructionRequest
):

    try:
        result = reconstruct_incident(
            request.records
        )

        return {
            "project": "AEGIS-X",
            "module": "ID2E-CHECK",
            "report_type": "INCIDENT_RECONSTRUCTION",
            **result
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        )


# --------------------------------------------------
# CREATE INCIDENT
# --------------------------------------------------

@router.post("/")
def create_incident(
    request: CreateIncidentRequest,
    db: Session = Depends(get_db)
):

    incident_id = str(uuid4())

    session_id = (
        request.session_id
        or str(uuid4())
    )

    incident = IncidentDB(
        incident_id=incident_id,
        session_id=session_id,
        title=request.title,
        status="OPEN",
        created_at=datetime.now(
            timezone.utc
        ).isoformat()
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {
        "project": "AEGIS-X",
        "incident_id": incident.incident_id,
        "session_id": incident.session_id,
        "title": incident.title,
        "status": incident.status,
        "created_at": incident.created_at
    }


# --------------------------------------------------
# LINK EVIDENCE TO INCIDENT
# --------------------------------------------------

@router.post("/{incident_id}/evidence/{evidence_id}")
def link_evidence_to_incident(
    incident_id: str,
    evidence_id: str,
    db: Session = Depends(get_db)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    evidence = db.get(
        EvidenceDB,
        evidence_id
    )

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence record not found"
        )

    existing_link = db.get(
        IncidentEvidenceDB,
        (incident_id, evidence_id)
    )

    if existing_link is not None:
        return {
            "status": "ALREADY_LINKED",
            "incident_id": incident_id,
            "evidence_id": evidence_id
        }

    link = IncidentEvidenceDB(
        incident_id=incident_id,
        evidence_id=evidence_id,
        linked_at=datetime.now(
            timezone.utc
        ).isoformat()
    )

    db.add(link)
    db.commit()

    return {
        "status": "LINKED",
        "incident_id": incident.incident_id,
        "session_id": incident.session_id,
        "evidence_id": evidence_id
    }


# --------------------------------------------------
# GET INCIDENT DETAILS
# --------------------------------------------------

@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    links = (
        db.query(IncidentEvidenceDB)
        .filter(
            IncidentEvidenceDB.incident_id == incident_id
        )
        .all()
    )

    return {
        "incident_id": incident.incident_id,
        "session_id": incident.session_id,
        "title": incident.title,
        "status": incident.status,
        "created_at": incident.created_at,
        "total_evidence_records": len(links)
    }


# --------------------------------------------------
# GET INCIDENT EVIDENCE
# --------------------------------------------------

@router.get("/{incident_id}/evidence")
def get_incident_evidence(
    incident_id: str,
    db: Session = Depends(get_db)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    records = get_incident_records(
        incident_id,
        db
    )

    return {
        "incident_id": incident.incident_id,
        "session_id": incident.session_id,
        "total_events": len(records),
        "records": [
            record.model_dump(mode="json")
            for record in records
        ]
    }


# --------------------------------------------------
# GET SESSION EVIDENCE
# --------------------------------------------------

@router.get("/sessions/{session_id}/evidence")
def get_session_evidence(
    session_id: str,
    db: Session = Depends(get_db)
):

    incidents = (
        db.query(IncidentDB)
        .filter(
            IncidentDB.session_id == session_id
        )
        .all()
    )

    if not incidents:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )

    incident_ids = [
        incident.incident_id
        for incident in incidents
    ]

    links = (
        db.query(IncidentEvidenceDB)
        .filter(
            IncidentEvidenceDB.incident_id.in_(
                incident_ids
            )
        )
        .all()
    )

    records = []

    for link in links:

        evidence = db.get(
            EvidenceDB,
            link.evidence_id
        )

        if evidence is not None:
            records.append(
                convert_database_evidence(evidence)
            )

    records.sort(
        key=lambda record: record.timestamp
    )

    return {
        "session_id": session_id,
        "total_incidents": len(incidents),
        "total_events": len(records),
        "records": [
            record.model_dump(mode="json")
            for record in records
        ]
    }


# --------------------------------------------------
# INTEGRITY-AWARE STORED INCIDENT RECONSTRUCTION
# --------------------------------------------------

@router.post("/{incident_id}/reconstruct")
def reconstruct_stored_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    records = get_incident_records(
        incident_id,
        db
    )

    try:

        # Verify every stored evidence record.
        integrity_results = {}

        for record in records:
            integrity_results[record.evidence_id] = (
                verify_stored_evidence(
                    db,
                    record.evidence_id
                )
            )

        # Reconstruct timeline with integrity findings.
        result = reconstruct_incident(
            records,
            integrity_results=integrity_results
        )

        return {
            "project": "AEGIS-X",
            "module": "ID2E-CHECK",
            "report_type": "STORED_INCIDENT_RECONSTRUCTION",
            "incident_id": incident.incident_id,
            "session_id": incident.session_id,
            **result
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        )
