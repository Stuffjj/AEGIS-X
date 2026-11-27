
from backend.app.models.evidence import EvidenceRecord


def test_evidence_record_creation():
    evidence = EvidenceRecord(
        identity="test-user-001",
        principal_type="human",
        action="Login attempt",
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Test session created",
        source="synthetic-lab"
    )

    assert evidence.identity == "test-user-001"
    assert evidence.action == "Login attempt"
    assert evidence.authorization_status == "authorized"
    assert evidence.execution_status == "success"
    assert evidence.evidence_id is not None
