from sqlalchemy import (
    String,
    Text,
    ForeignKey,
    PrimaryKeyConstraint
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class IncidentDB(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True
    )

    session_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True
    )

    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="OPEN"
    )

    created_at: Mapped[str] = mapped_column(
        String(40),
        nullable=False
    )


class IncidentEvidenceDB(Base):
    __tablename__ = "incident_evidence"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False
    )

    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_records.evidence_id", ondelete="CASCADE"),
        nullable=False
    )

    linked_at: Mapped[str] = mapped_column(
        String(40),
        nullable=False
    )

    __table_args__ = (
        PrimaryKeyConstraint(
            "incident_id",
            "evidence_id"
        ),
    )