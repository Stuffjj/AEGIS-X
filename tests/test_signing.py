
from backend.app.models.evidence import EvidenceRecord

from backend.app.core.signing import (
    generate_key_pair,
    sign_evidence,
    verify_signature
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


def test_key_pair_generation():

    private_key, public_key = generate_key_pair()

    assert len(private_key) > 0
    assert len(public_key) > 0


def test_valid_signature():

    evidence = create_test_evidence()

    private_key, public_key = generate_key_pair()

    signature = sign_evidence(evidence, private_key)

    assert verify_signature(
        evidence,
        signature,
        public_key
    ) is True


def test_modified_evidence_signature_failure():

    evidence = create_test_evidence()

    private_key, public_key = generate_key_pair()

    signature = sign_evidence(evidence, private_key)

    modified_evidence = evidence.model_copy(
        update={"action": "Unauthorized file access"}
    )

    assert verify_signature(
        modified_evidence,
        signature,
        public_key
    ) is False


def test_wrong_public_key_failure():

    evidence = create_test_evidence()

    private_key, public_key = generate_key_pair()

    signature = sign_evidence(evidence, private_key)

    _, wrong_public_key = generate_key_pair()

    assert verify_signature(
        evidence,
        signature,
        wrong_public_key
    ) is False
