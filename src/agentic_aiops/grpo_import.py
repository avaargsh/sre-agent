"""Fail-closed import of frozen AIOps scenario into the offline GRPO contract.

Source evidence and Oracle approval are separate inputs, pinned by independent
SHA256 digests. This verifies *content integrity*, NOT signer or issuer trust.
Never infer ground truth from hypotheses/outcome inside the source scenario.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .grpo_training import (
    READ_ONLY_TOOLS,
    SCHEMA,
    _decode_episode,
    _fields,
    _id,
    _strict_json,
    _read_bounded_bytes,
    _text,
)

_APPROVAL_SCHEMA = "sre.grpo.import-approval/v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 4 * 1024 * 1024
_MAX_EVIDENCE = 32


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_json(path: str | Path, *, name: str) -> tuple[bytes, Any]:
    raw = _read_bounded_bytes(path, limit=_MAX_BYTES, name=name)
    try:
        data = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid UTF-8 {name}") from exc
    return raw, data


def _sha(value: Any, name: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise ValueError(f"invalid {name}: expected lowercase sha256")
    return value


def _verify_pin(raw: bytes, expected: Any, name: str) -> str:
    approved = _sha(expected, name)
    actual = _digest(raw)
    if not hmac.compare_digest(actual, approved):
        raise ValueError(f"{name} mismatch")
    return actual


def _publish_episode_create_only(output: str | Path, row_bytes: bytes) -> None:
    """Atomically publish one complete Episode without overwriting prior work.

    A staging write/fsync failure must not create the final dataset path.
    Hard linking a flushed file publishes it only after all bytes are written,
    without replacing a concurrent writer's existing destination.
    """
    destination = Path(output)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Episode output already exists: {destination}")
    stage: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".sre-episode-stage-",
            dir=destination.parent, delete=False,
        ) as stream:
            stage = Path(stream.name)
            stream.write(row_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, destination)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


def import_scenario_episode(
    scenario_file: str | Path,
    approval_file: str | Path,
    *,
    expected_approval_sha256: str,
    output: str | Path,
) -> dict[str, Any]:
    """Import a *single* episode with no pre-existing output overwrite.

    Importer validates and fingerprints the source exactly as stored. The
    approval must be authored independently of the investigator/model and
    its SHA256 must be supplied out-of-band by the data owner.
    """
    raw_approval, approval_data = _load_json(approval_file, name="approval")
    approval_sha = _verify_pin(
        raw_approval, expected_approval_sha256, "approval_sha256"
    )
    approval = _fields(approval_data, {
        "schema_version", "case_id", "episode_id", "fault_family", "split",
        "source_sha256", "evidence_tools", "oracle",
    }, "approval")
    if approval["schema_version"] != _APPROVAL_SCHEMA:
        raise ValueError("unsupported approval schema_version")

    raw_source, scenario_data = _load_json(scenario_file, name="source scenario")
    source_sha = _verify_pin(raw_source, approval["source_sha256"], "source_sha256")
    scenario = _fields(scenario_data, {"case_id", "bundle", "outcome"}, "scenario")
    case_id = _id(approval["case_id"], "case_id")
    if scenario["case_id"] != case_id:
        raise ValueError("scenario case_id does not match approval case_id")
    bundle = _fields(scenario["bundle"], {
        "incident", "evidence", "hypotheses", "entities", "edges",
        "changes", "metadata",
    }, "evidence bundle")
    incident = bundle["incident"]
    if type(incident) is not dict:
        raise ValueError("invalid source incident")
    alert = _text(incident.get("summary"), "incident summary", 1024)

    evidence = bundle["evidence"]
    if type(evidence) is not list or not 1 <= len(evidence) <= _MAX_EVIDENCE:
        raise ValueError("source evidence must contain 1-32 records")
    approved_tools = approval["evidence_tools"]
    if type(approved_tools) is not dict:
        raise ValueError("evidence_tools must be an object")
    ids: set[str] = set()
    observations: list[dict[str, str]] = []
    for item in evidence:
        if type(item) is not dict:
            raise ValueError("invalid source evidence")
        evidence_id = _id(item.get("evidence_id"), "evidence_id")
        if evidence_id in ids:
            raise ValueError(f"duplicate source evidence_id: {evidence_id}")
        ids.add(evidence_id)
        source = item.get("source")
        if type(source) is not str or source not in {"kubernetes", "prometheus"}:
            raise ValueError(f"unsupported read-only evidence source: {source}")
        tool = approved_tools.get(evidence_id)
        if type(tool) is not str or tool not in READ_ONLY_TOOLS:
            raise ValueError(f"unsupported or non-read-only approved tool: {tool}")
        if not tool.startswith(source + "."):
            raise ValueError("approved tool source mismatch")
        observations.append({
            "evidence_id": evidence_id,
            "tool": tool,
            "text": _text(item.get("observation"), "observation", 4096),
        })
    if set(approved_tools) != ids:
        raise ValueError("evidence_tools must map exactly all source evidence IDs")

    payload = {
        "schema_version": SCHEMA,
        "episode_id": approval["episode_id"],
        "fault_family": approval["fault_family"],
        "split": approval["split"],
        "alert": alert,
        "observations": observations,
        "oracle": approval["oracle"],
    }
    # Reuse strict Episode validator: do not bypass train/test split and
    # correct-abstention invariants just because the input has a pinned SHA.
    episode = _decode_episode(payload)
    row = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False) + "\n"
    row_bytes = row.encode("utf-8")
    if len(row_bytes) > 32 * 1024:
        raise ValueError("converted Episode exceeds JSONL record budget")

    # Publish only a complete, fsynced JSONL record. A staging or link
    # failure cannot leave a partial final path. Multi-Episode assembly must
    # still use load_episodes for independent split/leakage validation.
    _publish_episode_create_only(output, row_bytes)

    metadata = bundle["metadata"]
    source_classification = "unclassified"
    if type(metadata) is dict and metadata.get("source") == "synthetic-regression":
        source_classification = "synthetic-regression"
    return {
        "schema_version": "sre.grpo.import-receipt/v1",
        "case_id": case_id,
        "episode_id": episode.episode_id,
        "source_sha256": source_sha,
        "approval_sha256": approval_sha,
        "episode_sha256": _digest(row_bytes),
        "source_classification": source_classification,
        "independent_issuer_verified": False,
        "live_fault_injection_verified": False,
    }
