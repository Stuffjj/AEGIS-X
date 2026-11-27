
from backend.app.models.evidence import EvidenceRecord

from backend.app.core.integrity import (
    calculate_sha256,
    verify_integrity
)


def create_test_evidence():
    return EvidenceRecord(
        identity="test-user-001",
        principal_type="human",
        action="Login attempt",
        resource="Test application",
        authorization_status="authorized",
        execution_status="success",
        observed_effect="Test session created",
        source="synthetic-lab"
    )


def test_sha256_hash_generation():
    evidence = create_test_evidence()

    evidence_hash = calculate_sha256(evidence)

    assert len(evidence_hash) == 64


def test_original_evidence_integrity():
    evidence = create_test_evidence()

    original_hash = calculate_sha256(evidence)

    assert verify_integrity(evidence, original_hash) is True


def test_tampered_evidence_detection():
    evidence = create_test_evidence()

    original_hash = calculate_sha256(evidence)

    modified_evidence = evidence.model_copy(
        update={"action": "Unauthorized file access"}
    )

    assert verify_integrity(
        modified_evidence,
        original_hash
    ) is False
