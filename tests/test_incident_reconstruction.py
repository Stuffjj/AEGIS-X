
from datetime import datetime, timezone, timedelta

from backend.app.models.evidence import EvidenceRecord

from backend.app.services.incident_reconstruction import (
    reconstruct_incident
)


def create_event(
    action,
    minutes,
    authorization="authorized",
    execution="success"
):
    return EvidenceRecord(
        identity="test-user-001",
        principal_type="human",
        action=action,
        resource="Test application",
        authorization_status=authorization,
        execution_status=execution,
        observed_effect="Synthetic test event",
        source="synthetic-lab",
        timestamp=datetime.now(timezone.utc)
        + timedelta(minutes=minutes)
    )


def test_incident_timeline_reconstruction():

    records = [
        create_event("Resource accessed", 2),
        create_event("Login attempt", 0),
        create_event("Permission checked", 1)
    ]

    result = reconstruct_incident(records)

    assert result["total_events"] == 3
    assert result["timeline"][0]["action"] == "Login attempt"
    assert result["timeline"][1]["action"] == "Permission checked"
    assert result["timeline"][2]["action"] == "Resource accessed"
    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"


def test_authorization_execution_contradiction():

    records = [
        create_event(
            "Restricted resource access",
            0,
            authorization="denied",
            execution="success"
        )
    ]

    result = reconstruct_incident(records)

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert (
        result["findings"][0]["finding"]
        == "AUTHORIZATION_EXECUTION_CONTRADICTION"
    )


def test_unknown_authorization_detection():

    records = [
        create_event(
            "Application access",
            0,
            authorization="unknown"
        )
    ]

    result = reconstruct_incident(records)

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert (
        result["findings"][0]["finding"]
        == "UNKNOWN_AUTHORIZATION"
    )


def test_empty_incident_reconstruction():

    result = reconstruct_incident([])

    assert result["total_events"] == 0
    assert result["timeline"] == []
    assert result["status"] == "NO_EVIDENCE"


# -----------------------------------------
# ID2E-CHECK INTEGRITY VERIFICATION TESTS
# -----------------------------------------


def test_valid_evidence_integrity():

    record = create_event("Login attempt", 0)

    result = reconstruct_incident(
        [record],
        integrity_results={
            record.evidence_id: True
        }
    )

    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"
    assert result["timeline"][0]["integrity_valid"] is True
    assert (
        result["timeline"][0]["integrity_status"]
        == "INTEGRITY_VALID"
    )
    assert result["findings"] == []


def test_evidence_integrity_failure():

    record = create_event("Unauthorized file access", 0)

    result = reconstruct_incident(
        [record],
        integrity_results={
            record.evidence_id: False
        }
    )

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert result["timeline"][0]["integrity_valid"] is False
    assert (
        result["timeline"][0]["integrity_status"]
        == "INTEGRITY_FAILURE"
    )

    assert any(
        finding["finding"] == "EVIDENCE_INTEGRITY_FAILURE"
        and finding["severity"] == "HIGH"
        for finding in result["findings"]
    )


def test_missing_integrity_result():

    record = create_event("Application access", 0)

    result = reconstruct_incident(
        [record],
        integrity_results={}
    )

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert result["timeline"][0]["integrity_valid"] is None
    assert (
        result["timeline"][0]["integrity_status"]
        == "NOT_VERIFIED"
    )

    assert any(
        finding["finding"] == "EVIDENCE_INTEGRITY_NOT_VERIFIED"
        for finding in result["findings"]
    )


def test_multiple_evidence_integrity_failures():

    record_one = create_event("File access", 0)
    record_two = create_event("Privilege change", 1)

    result = reconstruct_incident(
        [record_one, record_two],
        integrity_results={
            record_one.evidence_id: False,
            record_two.evidence_id: False
        }
    )

    integrity_findings = [
        finding
        for finding in result["findings"]
        if finding["finding"] == "EVIDENCE_INTEGRITY_FAILURE"
    ]

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert len(integrity_findings) == 2


def test_integrity_failure_overrides_clean_incident_status():

    record = create_event("Normal login", 0)

    result = reconstruct_incident(
        [record],
        integrity_results={
            record.evidence_id: False
        }
    )

    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert len(result["findings"]) >= 1


def test_legacy_reconstruction_without_integrity_results():

    record = create_event("Normal login", 0)

    result = reconstruct_incident([record])

    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"
    assert result["findings"] == []
    assert "integrity_valid" not in result["timeline"][0]
