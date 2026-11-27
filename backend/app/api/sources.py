
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.key_manager import (
    load_or_create_provenance_keys
)
from backend.app.core.provenance_signing import (
    sign_provenance,
    verify_provenance_signature
)
from backend.app.models.evidence_db import EvidenceDB
from backend.app.models.source_db import (
    EvidenceSourceDB,
    EvidenceProvenanceDB
)


router = APIRouter(
    prefix="/sources",
    tags=["Evidence Source Trust"]
)


class SourceRegistrationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source_type: str = Field(min_length=1, max_length=100)
    owner: str = Field(min_length=1, max_length=200)
    description: str | None = None


class SourceTrustUpdateRequest(BaseModel):
    trust_level: str


class ProvenanceRequest(BaseModel):
    evidence_id: str
    collector_identity: str = Field(
        min_length=1,
        max_length=200
    )
    collection_method: str = Field(
        min_length=1,
        max_length=200
    )
    transfer_details: str | None = None


VALID_TRUST_LEVELS = {
    "TRUSTED",
    "LIMITED",
    "UNVERIFIED"
}


def get_source_or_404(source_id: str, db: Session):
    source = db.get(EvidenceSourceDB, source_id)

    if source is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence source not found"
        )

    return source


@router.post("/")
def register_source(
    request: SourceRegistrationRequest,
    db: Session = Depends(get_db)
):
    source = EvidenceSourceDB(
        source_id=str(uuid4()),
        name=request.name,
        source_type=request.source_type,
        owner=request.owner,
        trust_level="UNVERIFIED",
        status="ACTIVE",
        description=request.description,
        registered_at=datetime.now(
            timezone.utc
        ).isoformat()
    )

    db.add(source)
    db.commit()
    db.refresh(source)

    return {
        "source_id": source.source_id,
        "name": source.name,
        "source_type": source.source_type,
        "owner": source.owner,
        "trust_level": source.trust_level,
        "status": source.status,
        "registered_at": source.registered_at
    }


@router.get("/")
def list_sources(
    db: Session = Depends(get_db)
):
    sources = (
        db.query(EvidenceSourceDB)
        .order_by(EvidenceSourceDB.registered_at.desc())
        .all()
    )

    return {
        "total": len(sources),
        "sources": [
            {
                "source_id": source.source_id,
                "name": source.name,
                "source_type": source.source_type,
                "owner": source.owner,
                "trust_level": source.trust_level,
                "status": source.status
            }
            for source in sources
        ]
    }


@router.get("/{source_id}")
def get_source(
    source_id: str,
    db: Session = Depends(get_db)
):
    source = get_source_or_404(source_id, db)

    return {
        "source_id": source.source_id,
        "name": source.name,
        "source_type": source.source_type,
        "owner": source.owner,
        "trust_level": source.trust_level,
        "status": source.status,
        "description": source.description,
        "registered_at": source.registered_at
    }


@router.patch("/{source_id}/trust")
def update_source_trust(
    source_id: str,
    request: SourceTrustUpdateRequest,
    db: Session = Depends(get_db)
):
    source = get_source_or_404(source_id, db)

    trust_level = request.trust_level.upper()

    if trust_level not in VALID_TRUST_LEVELS:
        raise HTTPException(
            status_code=422,
            detail="Invalid trust level"
        )

    if source.status == "REVOKED":
        raise HTTPException(
            status_code=409,
            detail="Revoked sources cannot have their trust level updated"
        )

    source.trust_level = trust_level

    db.commit()
    db.refresh(source)

    return {
        "source_id": source.source_id,
        "trust_level": source.trust_level,
        "status": source.status
    }


@router.post("/{source_id}/revoke")
def revoke_source(
    source_id: str,
    db: Session = Depends(get_db)
):
    source = get_source_or_404(source_id, db)

    source.status = "REVOKED"
    source.trust_level = "UNVERIFIED"

    db.commit()

    return {
        "source_id": source.source_id,
        "status": source.status,
        "trust_level": source.trust_level
    }


@router.post("/{source_id}/provenance")
def register_provenance(
    source_id: str,
    request: ProvenanceRequest,
    db: Session = Depends(get_db)
):
    source = get_source_or_404(source_id, db)

    if source.status != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail="Cannot associate evidence with an inactive source"
        )

    evidence = db.get(
        EvidenceDB,
        request.evidence_id
    )

    if evidence is None:
        raise HTTPException(
            status_code=404,
            detail="Evidence record not found"
        )

    provenance = EvidenceProvenanceDB(
        provenance_id=str(uuid4()),
        evidence_id=request.evidence_id,
        source_id=source_id,
        collector_identity=request.collector_identity,
        collection_method=request.collection_method,
        collected_at=datetime.now(
            timezone.utc
        ).isoformat(),
        transfer_details=request.transfer_details,
        signature_algorithm="Ed25519"
    )

    # Load the persistent platform signing keys.
    private_key, public_key = (
        load_or_create_provenance_keys()
    )

    # Sign the canonical provenance metadata.
    provenance.signature = sign_provenance(
        provenance,
        private_key
    )

    # Store the public key for verification metadata.
    # The private key is never stored in the database.
    provenance.public_key = public_key

    db.add(provenance)
    db.commit()
    db.refresh(provenance)

    return {
        "provenance_id": provenance.provenance_id,
        "evidence_id": provenance.evidence_id,
        "source_id": provenance.source_id,
        "source_trust_level": source.trust_level,
        "collector_identity": provenance.collector_identity,
        "collection_method": provenance.collection_method,
        "collected_at": provenance.collected_at,
        "signature_algorithm": provenance.signature_algorithm,
        "signature_status": "SIGNED",
        "signature": provenance.signature
    }


@router.get("/{source_id}/provenance")
def get_source_provenance(
    source_id: str,
    db: Session = Depends(get_db)
):
    source = get_source_or_404(source_id, db)

    records = (
        db.query(EvidenceProvenanceDB)
        .filter(
            EvidenceProvenanceDB.source_id == source_id
        )
        .order_by(
            EvidenceProvenanceDB.collected_at.asc()
        )
        .all()
    )

    return {
        "source_id": source.source_id,
        "source_name": source.name,
        "trust_level": source.trust_level,
        "source_status": source.status,
        "total_records": len(records),
        "provenance": [
            {
                "provenance_id": record.provenance_id,
                "evidence_id": record.evidence_id,
                "collector_identity": record.collector_identity,
                "collection_method": record.collection_method,
                "collected_at": record.collected_at,
                "transfer_details": record.transfer_details,
                "signature_algorithm": record.signature_algorithm,
                "signature_status": (
                    "SIGNED"
                    if record.signature
                    else "NOT_SIGNED"
                )
            }
            for record in records
        ]
    }


@router.get(
    "/{source_id}/provenance/{provenance_id}/verify"
)
def verify_provenance(
    source_id: str,
    provenance_id: str,
    db: Session = Depends(get_db)
):
    get_source_or_404(source_id, db)

    provenance = (
        db.query(EvidenceProvenanceDB)
        .filter(
            EvidenceProvenanceDB.source_id == source_id,
            EvidenceProvenanceDB.provenance_id == provenance_id
        )
        .first()
    )

    if provenance is None:
        raise HTTPException(
            status_code=404,
            detail="Provenance record not found"
        )

    if not provenance.signature or not provenance.public_key:
        return {
            "provenance_id": provenance.provenance_id,
            "signature_status": "NOT_SIGNED",
            "signature_valid": None,
            "message": "This provenance record has no stored signature."
        }

    if provenance.signature_algorithm != "Ed25519":
        return {
            "provenance_id": provenance.provenance_id,
            "signature_status": "UNSUPPORTED_ALGORITHM",
            "signature_valid": False,
            "signature_algorithm": provenance.signature_algorithm
        }

    # Use the locally protected public key as the trust anchor.
    # Do not blindly trust a public key stored alongside the record.
    try:
        _, trusted_public_key = load_or_create_provenance_keys()
    except (ValueError, RuntimeError):
        raise HTTPException(
            status_code=500,
            detail="Trusted provenance key is unavailable or inconsistent"
        )

    # Detect replacement of the stored public key.
    if provenance.public_key != trusted_public_key:
        signature_valid = False
    else:
        signature_valid = verify_provenance_signature(
            provenance,
            provenance.signature,
            trusted_public_key
        )

    return {
        "provenance_id": provenance.provenance_id,
        "evidence_id": provenance.evidence_id,
        "source_id": provenance.source_id,
        "signature_algorithm": provenance.signature_algorithm,
        "signature_status": (
            "VERIFIED"
            if signature_valid
            else "SIGNATURE_INVALID"
        ),
        "signature_valid": signature_valid,
        "message": (
            "The provenance signature is valid."
            if signature_valid
            else "The provenance signature or signed metadata is invalid."
        )
    }
