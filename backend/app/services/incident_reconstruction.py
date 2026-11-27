
from backend.app.models.evidence import EvidenceRecord


def reconstruct_incident(
    records: list[EvidenceRecord],
    integrity_results: dict[str, bool] | None = None
) -> dict:
    """
    Reconstruct a chronological incident timeline.

    Detects:
    - Authorization and execution contradictions.
    - Unknown authorization.
    - Evidence integrity failures when integrity results
      are supplied by the storage verification service.
    """

    if not records:
        return {
            "total_events": 0,
            "timeline": [],
            "findings": [],
            "status": "NO_EVIDENCE"
        }

    # Validate timestamps before sorting.
    for record in records:
        if (
            record.timestamp.tzinfo is None
            or record.timestamp.utcoffset() is None
        ):
            raise ValueError(
                "All evidence timestamps must include a timezone"
            )

    # Sort chronologically without modifying original records.
    sorted_records = sorted(
        records,
        key=lambda record: record.timestamp
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
            "source": record.source
        }

        # --------------------------------------------------
        # EVIDENCE INTEGRITY VERIFICATION
        # --------------------------------------------------

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
                    )
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
                    )
                })

            else:
                event["integrity_valid"] = True
                event["integrity_status"] = "INTEGRITY_VALID"

        timeline.append(event)

        # --------------------------------------------------
        # AUTHORIZATION AND EXECUTION CONTRADICTION
        # --------------------------------------------------

        if (
            record.authorization_status == "denied"
            and record.execution_status == "success"
        ):
            findings.append({
                "evidence_id": record.evidence_id,
                "severity": "HIGH",
                "finding": "AUTHORIZATION_EXECUTION_CONTRADICTION",
                "description": (
                    "Action was marked as denied but execution "
                    "was recorded as successful."
                )
            })

        # --------------------------------------------------
        # UNKNOWN AUTHORIZATION
        # --------------------------------------------------

        if record.authorization_status == "unknown":
            findings.append({
                "evidence_id": record.evidence_id,
                "severity": "MEDIUM",
                "finding": "UNKNOWN_AUTHORIZATION",
                "description": (
                    "Authorization status could not be established."
                )
            })

    return {
        "total_events": len(timeline),
        "timeline": timeline,
        "findings": findings,
        "status": (
            "REQUIRES_INVESTIGATION"
            if findings
            else "NO_INCONSISTENCIES_DETECTED"
        )
    }
