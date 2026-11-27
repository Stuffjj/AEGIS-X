
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class EvidenceSourceDB(Base):
    __tablename__ = "evidence_sources"

    source_id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    name: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    source_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    owner: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    trust_level: Mapped[str] = mapped_column(
        String(30), nullable=False, default="UNVERIFIED"
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="ACTIVE"
    )
    description: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    registered_at: Mapped[str] = mapped_column(
        String(40), nullable=False
    )


class EvidenceProvenanceDB(Base):
    __tablename__ = "evidence_provenance"

    provenance_id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_records.evidence_id"),
        nullable=False,
        index=True
    )
    source_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_sources.source_id"),
        nullable=False,
        index=True
    )
    collector_identity: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    collection_method: Mapped[str] = mapped_column(
        String(200), nullable=False
    )
    collected_at: Mapped[str] = mapped_column(
        String(40), nullable=False
    )
    transfer_details: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # Cryptographic provenance fields
    signature: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    public_key: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    signature_algorithm: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="Ed25519"
    )
