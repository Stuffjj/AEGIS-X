
from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class EvidenceCorrelationDB(Base):
    """
    Stores correlation metadata separately from original evidence.

    Keeping this separate preserves existing evidence hashes.
    """

    __tablename__ = "evidence_correlation"

    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "evidence_records.evidence_id",
            ondelete="CASCADE"
        ),
        primary_key=True
    )

    correlation_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True
    )

    session_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True
    )

    agent_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True
    )

    parent_event_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey(
            "evidence_records.evidence_id"
        ),
        nullable=True,
        index=True
    )

    created_at: Mapped[str] = mapped_column(
        String(40),
        nullable=False
    )
