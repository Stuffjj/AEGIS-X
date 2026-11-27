
from datetime import datetime, timezone, timedelta

from backend.app.models.evidence import EvidenceRecord

from backend.app.services.evidence_chain import (
    build_evidence_chain,
    verify_evidence_chain
)


def create_event(action, minutes):
    return EvidenceRecord(
        identity="test-user-001",
        principal_type="human",
        action=action,
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Test event recorded",
        source="synthetic-lab",
        timestamp=datetime.now(timezone.utc) + timedelta(
            minutes=minutes
        )
    )


def test_valid_evidence_chain():

    records = [
        create_event("Login attempt", 0),
        create_event("Access permission checked", 1),
        create_event("Resource accessed", 2)
    ]

    chain = build_evidence_chain(records)

    assert verify_evidence_chain(records, chain) is True


def test_modified_evidence_chain_detection():

    records = [
        create_event("Login attempt", 0),
        create_event("Resource accessed", 1)
    ]

    chain = build_evidence_chain(records)

    modified_records = list(records)

    modified_records[1] = records[1].model_copy(
        update={"action": "Unauthorized file access"}
    )

    assert verify_evidence_chain(
        modified_records, chain
    ) is False


def test_reordered_chain_detection():

    records = [
        create_event("Login attempt", 0),
        create_event("Permission checked", 1),
        create_event("Resource accessed", 2)
    ]

    chain = build_evidence_chain(records)

    reordered_records = [
        records[1],
        records[0],
        records[2]
    ]

    assert verify_evidence_chain(
        reordered_records, chain
    ) is False


def test_missing_evidence_detection():

    records = [
        create_event("Login attempt", 0),
        create_event("Permission checked", 1),
        create_event("Resource accessed", 2)
    ]

    chain = build_evidence_chain(records)

    incomplete_records = records[:2]

    assert verify_evidence_chain(
        incomplete_records, chain
    ) is False


def test_non_chronological_chain_rejected():

    records = [
        create_event("Resource accessed", 2),
        create_event("Login attempt", 0)
    ]

    try:
        build_evidence_chain(records)
        assert False, "Expected chronological validation failure"
    except ValueError as error:
        assert "chronological" in str(error)
