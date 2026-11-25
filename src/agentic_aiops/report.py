from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone

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


_TIMESTAMP = re.compile(
    r"(?P<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _timestamp_key(value: object) -> tuple[datetime, int] | None:
    if not isinstance(value, str):
        return None
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return None
    try:
        instant = datetime.fromisoformat(match["seconds"] + match["zone"])
        utc = instant.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None
    # Keep sub-microsecond ordering rather than truncating with datetime.
    fraction = int((match["fraction"] or "").ljust(9, "0"))
    return utc, fraction


def _incident_timeline(bundle: dict) -> tuple[list[dict], list[dict]]:
    events = [
        {
            "event_type": "evidence",
            "event_id": item["evidence_id"],
            "timestamp": item["timestamp"],
            "summary": item["observation"],
            "source": item["source"],
            "entity_refs": item["entity_refs"],
        }
        for item in bundle["evidence"]
    ] + [
        {
            "event_type": "change",
            "event_id": item["change_id"],
            "timestamp": item["timestamp"],
            "summary": item["summary"],
            "entity_id": item["entity_id"],
            "change_kind": item["kind"],
        }
        for item in bundle["changes"]
    ]
    dated = []
    undated = []
    for event in events:
        timestamp = event["timestamp"]
        key = _timestamp_key(timestamp)
        if key is None:
            event["timestamp_status"] = "missing" if timestamp is None else "invalid"
            undated.append(event)
        else:
            event["timestamp_status"] = "parsed"
            dated.append((key, event))
    dated.sort(key=lambda pair: pair[0])
    return [event for _, event in dated], undated


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
    timeline, undated_events = _incident_timeline(bundle)
    return json.dumps({
        "schema_version": "rca-report/v1",
        "independently_verified": False,
        "execution_authorized": False,
        "incident": bundle["incident"],
        "evidence": bundle["evidence"],
        "hypotheses": hypotheses,
        "timeline": timeline,
        "undated_events": undated_events,
        "duplicate_evidence_ids": sorted(key for key, count in counts.items() if count > 1),
    }, indent=2, allow_nan=False)
