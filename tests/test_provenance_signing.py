
from datetime import datetime, timezone
from uuid import uuid4

from backend.app.models.source_db import EvidenceProvenanceDB

from backend.app.core.provenance_signing import (
    generate_provenance_key_pair,
    sign_provenance,
    verify_provenance_signature,
    calculate_provenance_hash
)


def create_test_provenance():

    return EvidenceProvenanceDB(
        provenance_id=str(uuid4()),
        evidence_id=str(uuid4()),
        source_id=str(uuid4()),
        collector_identity="AEGIS-X-Test-Collector",
        collection_method="Synthetic Windows Event Collection",
        collected_at=datetime.now(timezone.utc).isoformat(),
        transfer_details="Isolated cybersecurity test environment"
    )


def test_provenance_key_pair_generation():

    private_key, public_key = generate_provenance_key_pair()

    assert private_key
    assert public_key
    assert private_key != public_key


def test_valid_provenance_signature():

    provenance = create_test_provenance()

    private_key, public_key = generate_provenance_key_pair()

    signature = sign_provenance(
        provenance,
        private_key
    )

    result = verify_provenance_signature(
        provenance,
        signature,
        public_key
    )

    assert result is True


def test_modified_provenance_signature_failure():

    provenance = create_test_provenance()

    private_key, public_key = generate_provenance_key_pair()

    signature = sign_provenance(
        provenance,
        private_key
    )

    # Simulate unauthorized provenance modification.
    provenance.collection_method = "Modified collection method"

    result = verify_provenance_signature(
        provenance,
        signature,
        public_key
    )

    assert result is False


def test_wrong_public_key_signature_failure():

    provenance = create_test_provenance()

    private_key, public_key = generate_provenance_key_pair()

    _, wrong_public_key = generate_provenance_key_pair()

    signature = sign_provenance(
        provenance,
        private_key
    )

    result = verify_provenance_signature(
        provenance,
        signature,
        wrong_public_key
    )

    assert result is False


def test_provenance_hash_consistency():

    provenance = create_test_provenance()

    first_hash = calculate_provenance_hash(provenance)
    second_hash = calculate_provenance_hash(provenance)

    assert first_hash == second_hash
    assert len(first_hash) == 64
