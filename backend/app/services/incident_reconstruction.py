
from typing import Any

from backend.app.models.evidence import EvidenceRecord
from backend.app.services.correlation_analysis import (
    analyze_correlations,
)


def reconstruct_incident(
    records: list[EvidenceRecord],
    integrity_results: dict[str, bool] | None = None,
    correlation_metadata: list[Any] | None = None,
) -> dict:
    """
    Reconstruct a chronological incident timeline.

    Detects:
    - Authorization and execution contradictions.
    - Unknown authorization.
    - Evidence integrity failures.
    - Correlation group identity variations.
    - Parent-event references outside the analysis set.
    """

    if not records:
        return {
            "total_events": 0,
            "timeline": [],
            "findings": [],
            "status": "NO_EVIDENCE",
        }

    for record in records:
        if (
            record.timestamp.tzinfo is None
            or record.timestamp.utcoffset() is None
        ):
            raise ValueError(
                "All evidence timestamps must include a timezone"
            )

    sorted_records = sorted(
        records,
        key=lambda record: record.timestamp,
    )

    timeline = []
    findings = []

    for sequence, record in enumerate(sorted_records, start=1):

        event = {
            "sequence": sequence,
            "evidence_id": record.evidence_id,
            "timestamp": record.timestamp.isoformat(),
            "identity": record.identity,
            "action": record.action,
            "resource": record.resource,
            "authorization_status": record.authorization_status,
            "execution_status": record.execution_status,
            "observed_effect": record.observed_effect,
            "source": record.source,
        }

        # Normalize status values to avoid case-sensitivity issues.
        authorization_status = (
            record.authorization_status.strip().lower()
        )

        execution_status = (
            record.execution_status.strip().lower()
        )

        # Evidence integrity verification.
        if integrity_results is not None:

            integrity_valid = integrity_results.get(
                record.evidence_id
            )

            if integrity_valid is None:
                event["integrity_valid"] = None
                event["integrity_status"] = "NOT_VERIFIED"

                findings.append({
                    "evidence_id": record.evidence_id,
                    "severity": "MEDIUM",
                    "finding": "EVIDENCE_INTEGRITY_NOT_VERIFIED",
                    "description": (
                        "Evidence integrity could not be verified."
                    ),
                })

            elif integrity_valid is False:
                event["integrity_valid"] = False
                event["integrity_status"] = "INTEGRITY_FAILURE"

                findings.append({
                    "evidence_id": record.evidence_id,
                    "severity": "HIGH",
                    "finding": "EVIDENCE_INTEGRITY_FAILURE",
                    "description": (
                        "The current evidence record does not match "
                        "its stored SHA-256 hash. The evidence may "
                        "have been modified after its original hash "
                        "was generated."
                    ),
                })

            else:
                event["integrity_valid"] = True
                event["integrity_status"] = "INTEGRITY_VALID"

        timeline.append(event)

        # Authorization and execution contradiction.
        if (
            authorization_status == "denied"
            and execution_status == "success"
        ):
            findings.append({
                "evidence_id": record.evidence_id,
                "severity": "HIGH",
                "finding": "AUTHORIZATION_EXECUTION_CONTRADICTION",
                "description": (
                    "Action was marked as denied but execution "
                    "was recorded as successful."
                ),
            })

        # Unknown authorization.
        if authorization_status == "unknown":
            findings.append({
                "evidence_id": record.evidence_id,
                "severity": "MEDIUM",
                "finding": "UNKNOWN_AUTHORIZATION",
                "description": (
                    "Authorization status could not be established."
                ),
            })

    result = {
        "total_events": len(timeline),
        "timeline": timeline,
        "findings": findings,
        "status": (
            "REQUIRES_INVESTIGATION"
            if findings
            else "NO_INCONSISTENCIES_DETECTED"
        ),
    }

    # ID2E-CHECK correlation analysis.
    if correlation_metadata is not None:

        correlation_result = analyze_correlations(
            sorted_records,
            correlation_metadata,
        )

        result["correlation_analysis"] = correlation_result

        findings.extend(correlation_result["findings"])

        if findings:
            result["status"] = "REQUIRES_INVESTIGATION"

    return result
