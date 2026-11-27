
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

from backend.app.models.evidence import EvidenceRecord
from backend.app.services.incident_reconstruction import (
    reconstruct_incident,
)


def create_event(identity, action, minutes=0):
    return EvidenceRecord(
        identity=identity,
        principal_type="human",
        action=action,
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Synthetic test event",
        source="synthetic-lab",
        timestamp=datetime.now(timezone.utc)
        + timedelta(minutes=minutes),
    )


def create_metadata(
    evidence_id,
    correlation_id,
    session_id="SESSION-001",
    agent_id="AGENT-001",
    parent_event_id=None,
):
    return SimpleNamespace(
        evidence_id=evidence_id,
        correlation_id=correlation_id,
        session_id=session_id,
        agent_id=agent_id,
        parent_event_id=parent_event_id,
    )


def test_reconstruction_with_correlation_metadata():

    first = create_event("user-A", "Login")
    second = create_event("user-B", "Resource access", 1)

    metadata = [
        create_metadata(first.evidence_id, "CORR-001"),
        create_metadata(
            second.evidence_id,
            "CORR-001",
            parent_event_id=first.evidence_id,
        ),
    ]

    result = reconstruct_incident(
        [first, second],
        correlation_metadata=metadata,
    )

    analysis = result["correlation_analysis"]

    assert analysis["total_evidence"] == 2
    assert analysis["total_correlation_groups"] == 1
    assert analysis["groups"][0]["evidence_count"] == 2

    assert any(
        finding["finding"]
        == "IDENTITY_VARIATION_WITHIN_CORRELATION"
        for finding in result["findings"]
    )

    assert result["status"] == "REQUIRES_INVESTIGATION"


def test_reconstruction_with_valid_correlation():

    first = create_event("user-A", "Login")
    second = create_event("user-A", "Resource access", 1)

    metadata = [
        create_metadata(first.evidence_id, "CORR-002"),
        create_metadata(second.evidence_id, "CORR-002"),
    ]

    result = reconstruct_incident(
        [first, second],
        correlation_metadata=metadata,
    )

    assert result["correlation_analysis"]["total_correlation_groups"] == 1

    assert not any(
        finding["finding"]
        == "IDENTITY_VARIATION_WITHIN_CORRELATION"
        for finding in result["findings"]
    )

    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"


def test_reconstruction_without_correlation_metadata():

    record = create_event("user-A", "Normal login")

    result = reconstruct_incident([record])

    assert "correlation_analysis" not in result
    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"


def test_correlation_and_integrity_findings_together():

    record = create_event("user-A", "Login")

    metadata = [
        create_metadata(record.evidence_id, "CORR-003")
    ]

    result = reconstruct_incident(
        [record],
        integrity_results={
            record.evidence_id: False
        },
        correlation_metadata=metadata,
    )

    finding_types = [
        finding["finding"]
        for finding in result["findings"]
    ]

    assert "EVIDENCE_INTEGRITY_FAILURE" in finding_types
    assert result["status"] == "REQUIRES_INVESTIGATION"
