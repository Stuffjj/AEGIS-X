
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class EvidenceDB(Base):
    __tablename__ = "evidence_records"

    evidence_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True
    )

    identity: Mapped[str] = mapped_column(String(200))

    principal_type: Mapped[str] = mapped_column(String(50))

    action: Mapped[str] = mapped_column(String(500))

    resource: Mapped[str] = mapped_column(String(500))

    authorization_status: Mapped[str] = mapped_column(
        String(50)
    )

    execution_status: Mapped[str] = mapped_column(
        String(50)
    )

    observed_effect: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    source: Mapped[str] = mapped_column(String(200))

    timestamp: Mapped[str] = mapped_column(String(40))

    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )
