from collections import defaultdict
from typing import Any


def correlate_evidence(
    evidence_records: list[Any],
    correlation_metadata: list[Any],
) -> dict:
    """
    Group evidence using explicit correlation metadata.

    Priority:
    1. correlation_id
    2. session_id
    3. agent_id
    4. parent_event_id

    Evidence without correlation metadata remains ungrouped.
    """

    metadata_by_evidence = {
        item.evidence_id: item
        for item in correlation_metadata
    }

    groups = defaultdict(list)
    ungrouped = []

    for evidence in evidence_records:
        metadata = metadata_by_evidence.get(evidence.evidence_id)

        if metadata is None:
            ungrouped.append(evidence.evidence_id)
            continue

        group_type = None
        group_value = None

        for field in (
            "correlation_id",
            "session_id",
            "agent_id",
            "parent_event_id",
        ):
            value = getattr(metadata, field, None)

            if value:
                group_type = field
                group_value = value
                break

        if group_type is None:
            ungrouped.append(evidence.evidence_id)
            continue

        group_key = f"{group_type}:{group_value}"
        groups[group_key].append(evidence.evidence_id)

    return {
        "total_evidence": len(evidence_records),
        "total_groups": len(groups),
        "ungrouped_evidence": ungrouped,
        "groups": [
            {
                "group_id": group_key,
                "evidence_count": len(evidence_ids),
                "evidence_ids": evidence_ids,
            }
            for group_key, evidence_ids in groups.items()
        ],
    }