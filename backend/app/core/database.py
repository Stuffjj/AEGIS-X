
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'aegis_x.db'}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


class Base(DeclarativeBase):
    pass


def create_tables():
    # Evidence model
    from backend.app.models.evidence_db import EvidenceDB

    # Incident models
    from backend.app.models.incident_db import (
        IncidentDB,
        IncidentEvidenceDB
    )

    # Evidence source and provenance models
    from backend.app.models.source_db import (
        EvidenceSourceDB,
        EvidenceProvenanceDB
    )

    # ID2E-CHECK correlation model
    from backend.app.models.correlation_db import (
        EvidenceCorrelationDB
    )

    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
