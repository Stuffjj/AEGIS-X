
import hashlib
import json

from datetime import datetime

from backend.app.models.evidence import EvidenceRecord
from backend.app.core.integrity import calculate_sha256


GENESIS_HASH = "0" * 64


def canonical_json(data: dict) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def build_evidence_chain(records: list[EvidenceRecord]) -> list[dict]:
    """
    Build an ordered, hash-linked evidence chain.
    Input order is preserved. Records are not silently sorted.
    """

    chain = []
    previous_hash = GENESIS_HASH
    previous_timestamp = None

    for sequence, record in enumerate(records, start=1):

        timestamp = record.timestamp

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Evidence timestamps must include a timezone")

        if (
            previous_timestamp is not None
            and timestamp < previous_timestamp
        ):
            raise ValueError(
                "Evidence records are not in chronological order"
            )

        evidence_hash = calculate_sha256(record)

        chain_data = {
            "sequence": sequence,
            "evidence_id": record.evidence_id,
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash
        }

        chain_hash = hashlib.sha256(
            canonical_json(chain_data).encode("utf-8")
        ).hexdigest()

        chain_entry = {
            **chain_data,
            "chain_hash": chain_hash
        }

        chain.append(chain_entry)

        previous_hash = chain_hash
        previous_timestamp = timestamp

    return chain


def verify_evidence_chain(
    records: list[EvidenceRecord],
    chain: list[dict]
) -> bool:
    """
    Verify evidence hashes, ordering and chain linkage.
    """

    if len(records) != len(chain):
        return False

    previous_hash = GENESIS_HASH
    previous_timestamp = None

    for sequence, (record, entry) in enumerate(
        zip(records, chain), start=1
    ):

        timestamp = record.timestamp

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return False

        if (
            previous_timestamp is not None
            and timestamp < previous_timestamp
        ):
            return False

        evidence_hash = calculate_sha256(record)

        if entry.get("sequence") != sequence:
            return False

        if entry.get("evidence_id") != record.evidence_id:
            return False

        if entry.get("evidence_hash") != evidence_hash:
            return False

        if entry.get("previous_hash") != previous_hash:
            return False

        chain_data = {
            "sequence": sequence,
            "evidence_id": record.evidence_id,
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash
        }

        expected_chain_hash = hashlib.sha256(
            canonical_json(chain_data).encode("utf-8")
        ).hexdigest()

        if entry.get("chain_hash") != expected_chain_hash:
            return False

        previous_hash = expected_chain_hash
        previous_timestamp = timestamp

    return True
