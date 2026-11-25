from __future__ import annotations

import json
from collections import Counter

from .bundle import EvidenceBundle
from .models import VerificationStatus


def render_rca_markdown(bundle: EvidenceBundle) -> str:
    lines = [
        f"# Incident {bundle.incident.incident_id}",
        "",
        f"**Severity:** {bundle.incident.severity}",
        f"**Summary:** {bundle.incident.summary}",
    ]

    if bundle.incident.scope:
        lines.append(f"**Scope:** {bundle.incident.scope}")

    lines.extend(["", "## Evidence", ""])
    for item in bundle.evidence:
        lines.append(
            f"- `{item.evidence_id}` [{item.source}] {item.observation}"
        )

    lines.extend(["", "## Hypotheses", ""])
    for item in bundle.hypotheses:
        marker = {
            VerificationStatus.SUPPORTED: "SUPPORTED",
            VerificationStatus.REJECTED: "REJECTED",
            VerificationStatus.UNVERIFIED: "UNVERIFIED",
        }[item.status]
        evidence = ", ".join(item.evidence_ids) or "none"
        lines.append(
            f"- **{marker}** {item.statement} — evidence: {evidence}"
        )

    return "\n".join(lines) + "\n"


def render_rca_json(payload: dict) -> str:
    """Render supplied data with structural reference checks, not RCA verification."""
    def valid_id(value):
        return isinstance(value, str) and bool(value.strip())

    for field, id_field in (("evidence", "evidence_id"), ("hypotheses", "hypothesis_id")):
        items = payload.get(field, [])
        if not isinstance(items, list) or not all(
            isinstance(item, dict) and valid_id(item.get(id_field)) for item in items
        ):
            raise ValueError("invalid report identifiers")
    for item in payload.get("hypotheses", []):
        refs = item.get("evidence_ids", [])
        if not isinstance(refs, list) or not all(valid_id(ref) for ref in refs):
            raise ValueError("invalid evidence references")

    bundle = EvidenceBundle.from_dict(payload).to_dict()
    counts = Counter(item["evidence_id"] for item in bundle["evidence"])
    hypotheses = []
    for item in bundle["hypotheses"]:
        refs = item["evidence_ids"]
        missing = sorted({ref for ref in refs if counts[ref] == 0})
        ambiguous = sorted({ref for ref in refs if counts[ref] > 1})
        hypotheses.append({
            "hypothesis_id": item["hypothesis_id"],
            "statement": item["statement"],
            "supplied_status": item["status"],
            "evidence_ids": refs,
            "missing_evidence_ids": missing,
            "ambiguous_evidence_ids": ambiguous,
            "references_resolved": bool(refs) and not missing and not ambiguous,
        })
    return json.dumps({
        "schema_version": "rca-report/v1",
        "independently_verified": False,
        "execution_authorized": False,
        "incident": bundle["incident"],
        "evidence": bundle["evidence"],
        "hypotheses": hypotheses,
        "duplicate_evidence_ids": sorted(key for key, count in counts.items() if count > 1),
    }, indent=2, allow_nan=False)
