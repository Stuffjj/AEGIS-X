
from collections import defaultdict
from typing import Any


def analyze_correlations(
    evidence_records: list[Any],
    correlation_metadata: list[Any],
) -> dict:
    """
    Analyse explicit relationships between evidence records.

    Groups evidence by correlation_id.
    Reports session and agent context.
    Detects identity inconsistencies within groups.

    Matching identities alone does not establish a relationship.
    """

    evidence_ids = {
        record.evidence_id for record in evidence_records
    }

    metadata_by_id = {
        item.evidence_id: item
        for item in correlation_metadata
    }

    groups = defaultdict(list)
    ungrouped = []

    findings = []

    for evidence in evidence_records:
        metadata = metadata_by_id.get(evidence.evidence_id)

        if metadata is None or not metadata.correlation_id:
            ungrouped.append(evidence.evidence_id)
            continue

        groups[metadata.correlation_id].append(
            (evidence, metadata)
        )

    results = []

    for correlation_id, members in groups.items():

        identities = sorted({
            evidence.identity
            for evidence, metadata in members
        })

        sessions = sorted({
            metadata.session_id
            for evidence, metadata in members
            if metadata.session_id
        })

        agents = sorted({
            metadata.agent_id
            for evidence, metadata in members
            if metadata.agent_id
        })

        evidence_group_ids = [
            evidence.evidence_id
            for evidence, metadata in members
        ]

        parent_links = []

        for evidence, metadata in members:
            parent_id = metadata.parent_event_id

            if parent_id:
                parent_links.append({
                    "evidence_id": evidence.evidence_id,
                    "parent_event_id": parent_id,
                    "parent_in_analysis_set": (
                        parent_id in evidence_ids
                    ),
                })

                if parent_id not in evidence_ids:
                    findings.append({
                        "severity": "MEDIUM",
                        "finding": "PARENT_EVIDENCE_NOT_IN_ANALYSIS_SET",
                        "correlation_id": correlation_id,
                        "evidence_id": evidence.evidence_id,
                        "description": (
                            "A parent event is referenced but is not "
                            "included in the current analysis set."
                        ),
                    })

        if len(identities) > 1:
            findings.append({
                "severity": "MEDIUM",
                "finding": "IDENTITY_VARIATION_WITHIN_CORRELATION",
                "correlation_id": correlation_id,
                "evidence_ids": evidence_group_ids,
                "identities": identities,
                "description": (
                    "Multiple identities appear within the same "
                    "explicit correlation group. This requires "
                    "investigation and is not automatically malicious."
                ),
            })

        results.append({
            "correlation_id": correlation_id,
            "evidence_count": len(members),
            "evidence_ids": evidence_group_ids,
            "identities": identities,
            "session_ids": sessions,
            "agent_ids": agents,
            "parent_links": parent_links,
        })

    return {
        "total_evidence": len(evidence_records),
        "total_correlation_groups": len(results),
        "ungrouped_evidence": ungrouped,
        "groups": results,
        "findings": findings,
    }
