
import hashlib
import hmac
import json

from backend.app.models.evidence import EvidenceRecord


def canonicalize_evidence(record: EvidenceRecord) -> str:
    """
    Convert evidence into a consistent JSON representation.
    """

    evidence_data = record.model_dump(mode="json")

    return json.dumps(
        evidence_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def calculate_sha256(record: EvidenceRecord) -> str:
    """
    Generate a SHA-256 hash for an evidence record.
    """

    canonical_data = canonicalize_evidence(record)

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


def verify_integrity(
    record: EvidenceRecord,
    expected_hash: str
) -> bool:
    """
    Verify whether evidence matches its original hash.
    """

    actual_hash = calculate_sha256(record)

    return hmac.compare_digest(
        actual_hash,
        expected_hash
    )
