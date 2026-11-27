
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict


class EvidenceRecord(BaseModel):
    """
    ID2E-CHECK standardized security evidence record.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(
        default_factory=lambda: str(uuid4())
    )

    identity: str = Field(min_length=1, max_length=200)

    principal_type: str = Field(
        description="human, service, or AI agent"
    )

    action: str = Field(min_length=1, max_length=500)

    resource: str = Field(min_length=1, max_length=500)

    authorization_status: str = Field(
        description="authorized, denied, or unknown"
    )

    execution_status: str = Field(
        description="success, failure, or unknown"
    )

    observed_effect: Optional[str] = None

    source: str = Field(min_length=1, max_length=200)

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
