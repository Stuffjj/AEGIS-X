from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceCorrelation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=36)

    correlation_id: Optional[str] = Field(
        default=None, min_length=1, max_length=100
    )

    session_id: Optional[str] = Field(
        default=None, min_length=1, max_length=100
    )

    agent_id: Optional[str] = Field(
        default=None, min_length=1, max_length=100
    )

    parent_event_id: Optional[str] = Field(
        default=None, min_length=1, max_length=36
    )