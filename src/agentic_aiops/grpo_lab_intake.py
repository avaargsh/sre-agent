"""Offline intake of an unverified G2i NetworkPolicy lab *candidate*.

This adapter intentionally does NOT elevate an administrator's lab outcome
to a model-visible cause label. The G2i read-only observer never sees the
admin's NetworkPolicy; its correct diagnostic answer is UNKNOWN. The Go
G2i evaluator and v2 signed evidence verifier remain independent and live
in a separate Draft PR stack, not reimplemented or implicitly trusted here.

Both approval and source checks are necessary but not sufficient for issuer
authentication, actual Kubernetes provenance or a production release.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

from .grpo_import import _load_json, _verify_pin
from .grpo_training import SCHEMA, _decode_episode, _fields, _id, _strict_json

_PHASES = ("before", "during", "after")
_SOURCE_FIELDS = ("pod", "probe", "service", "endpoint_slices", "network_policy_list")
_EXPECTED_CLASS = {
    "before": "HEALTHY_NAME_AND_IP",
    "during": "UNKNOWN",
    "after": "HEALTHY_NAME_AND_IP",
}
_LAB_SCHEMA = "sre.grpo.networkpolicy-lab-approval/v1"
_EPISODE_SCHEMA = "sre.networkpolicy-oracle/v1"
_RESULT_SCHEMA = "sre.networkpolicy-evaluation/v1"
_MAX_RAW = 2 * 1024 * 1024
_MAX_EPISODE = 16 * 1024 * 1024


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or symlink source: {path.name}")
    # Bound reads by file size so a forged or corrupted lab artifact cannot
    # force unbounded memory use. These are offline, read-only artifacts.
    if not 0 < path.stat().st_size <= limit:
        raise ValueError(f"missing or oversized source: {path.name}")
    raw = path.read_bytes()
    if not 0 < len(raw) <= limit:
        raise ValueError(f"missing or oversized source: {path.name}")
    return raw


def _document(path: Path, limit: int) -> tuple[bytes, Any]:
    raw = _read_file(path, limit)
    try:
        value = _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid JSON text: {path.name}") from exc
    return raw, value


def _verified_snapshot(item: Any) -> bytes:
    source = _fields(item, {"response_sha256", "raw_response_base64"},
                     "snapshot")
    digest = source["response_sha256"]
    if type(digest) is not str or len(digest) != 64 or any(
        ch not in "0123456789abcdef" for ch in digest
    ):
        raise ValueError("invalid snapshot response_sha256")
    encoded = source["raw_response_base64"]
    if type(encoded) is not str or len(encoded) > (_MAX_RAW * 4 // 3 + 8):
        raise ValueError("oversized or invalid raw_response_base64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64 snapshot") from exc
    if not 0 < len(raw) <= _MAX_RAW or _digest(raw) != digest:
        raise ValueError("snapshot response_sha256 mismatch or invalid size")
    # All five G2i artifacts are native JSON sources.
    try:
        _strict_json(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("invalid snapshot UTF-8") from exc
    return raw


def _check_probe(raw: bytes, phase: str) -> dict[str, Any]:
    probe = _strict_json(raw.decode("utf-8"))
    if type(probe) is not dict or probe.get("schema_version") != "sre.dns-probe/v1":
        raise ValueError("unexpected read-only probe schema")
    if probe.get("host") != "checkout-api.golden-demo.svc.cluster.local":
        raise ValueError("unexpected probe host")
    try:
        ipaddress.ip_address(probe.get("service_ip"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid probe service_ip") from exc
    addresses = probe.get("dns_addresses")
    if type(addresses) is not list or probe["service_ip"] not in addresses:
        raise ValueError("DNS result does not match the Service IP")
    if probe.get("dns_ok") is not True or probe.get("dns_error") != "":
        raise ValueError("probe DNS must remain healthy")
    attempts = probe.get("direct_http_attempts")
    wanted = 0 if phase == "during" else 200
    if (
        type(attempts) is not list or len(attempts) != 3
        or any(type(code) is not int or code != wanted for code in attempts)
        or type(probe.get("name_http_status")) is not int
        or probe["name_http_status"] != wanted
        or type(probe.get("direct_http_status")) is not int
        or probe["direct_http_status"] != wanted
    ):
        raise ValueError("probe HTTP phases contradict lab pattern")
    return probe


def import_networkpolicy_lab_candidate(
    root: str | Path,
    approval_file: str | Path,
    *,
    expected_approval_sha256: str,
    output: str | Path,
) -> dict[str, Any]:
    """Produce UNKNOWN-only holdout candidate; never mark authenticated/training admitted."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("artifact root must be a real directory")
    raw_approval, approval = _load_json(approval_file, name="approval")
    approval_sha = _verify_pin(raw_approval, expected_approval_sha256,
                               "approval_sha256")
    approval = _fields(approval, {
        "schema_version", "episode_id", "output_episode_id", "fault_family",
        "split", "episode_sha256", "evaluation_sha256", "observer_log_sha256",
    }, "approval")
    if approval["schema_version"] != _LAB_SCHEMA:
        raise ValueError("unsupported lab approval schema")
    source_id = _id(approval["episode_id"], "episode_id")
    output_id = _id(approval["output_episode_id"], "output_episode_id")
    family = _id(approval["fault_family"], "fault_family")
    if approval["split"] not in ("test", "validation"):
        raise ValueError("unverified lab candidate may only enter a holdout split")
    hashes = _fields(approval["observer_log_sha256"], set(_PHASES),
                     "observer_log_sha256")

    raw_episode, episode = _document(root / "episode.json", _MAX_EPISODE)
    episode_sha = _verify_pin(raw_episode, approval["episode_sha256"],
                              "episode_sha256")
    episode = _fields(episode, {"schema_version", "episode_id", *_PHASES},
                      "lab episode")
    if episode["schema_version"] != _EPISODE_SCHEMA or episode["episode_id"] != source_id:
        raise ValueError("lab episode identity mismatch")

    raw_result, evaluation = _document(root / "evaluation.json", 128 * 1024)
    evaluation_sha = _verify_pin(raw_result, approval["evaluation_sha256"],
                                 "evaluation_sha256")
    evaluation = _fields(evaluation, {
        "schema_version", "episode_id", "status", "before_diagnostic",
        "during_diagnostic", "after_diagnostic",
        "production_causality_verified", "explanation",
    }, "lab evaluation")
    if (
        evaluation["schema_version"] != _RESULT_SCHEMA
        or evaluation["episode_id"] != source_id
        or evaluation["status"] != "MATCHED_LAB_NETWORK_POLICY_DENIAL"
        or evaluation["production_causality_verified"] is not False
        or any(evaluation[phase + "_diagnostic"] != classification
               for phase, classification in _EXPECTED_CLASS.items())
    ):
        raise ValueError("lab evaluation status/diagnostic is not accepted")

    frozen_logs: dict[str, bytes] = {}
    service_ips: set[str] = set()
    observations = []
    for phase in _PHASES:
        snapshots = _fields(episode[phase], set(_SOURCE_FIELDS),
                            f"{phase} snapshots")
        original = {key: _verified_snapshot(snapshots[key])
                    for key in _SOURCE_FIELDS}
        admin_raw = _read_file(root / f"{phase}-admin.log", 16 * 1024)
        observer_raw = _read_file(root / f"{phase}-observer.log", 16 * 1024)
        # These admin and observer bytes were separately captured by G2i;
        # equality alone does NOT authenticate cluster source.
        if admin_raw != observer_raw or original["probe"] != admin_raw:
            raise ValueError(f"{phase} admin and observer log mismatch")
        approved_hash = hashes[phase]
        if _verify_pin(observer_raw, approved_hash,
                       "observer_log_sha256") != _digest(original["probe"]):
            raise ValueError("observer_log_sha256 does not match snapshot")
        raw_obs, diagnosis = _document(
            root / f"{phase}-observation.json", 128 * 1024
        )
        diagnosis = _fields(diagnosis, {
            "schema_version", "classification", "host",
            "service_ip", "observed",
        }, "observer diagnosis")
        if (diagnosis["schema_version"] != "sre.dns-observation/v1"
                or diagnosis["classification"] != _EXPECTED_CLASS[phase]):
            raise ValueError(f"{phase} observer classification mismatch")
        if _verified_snapshot(diagnosis["observed"]) != observer_raw:
            raise ValueError("observer diagnosis refers to different source bytes")
        probe = _check_probe(observer_raw, phase)
        if diagnosis["host"] != probe["host"] or diagnosis["service_ip"] != probe["service_ip"]:
            raise ValueError("observer diagnosis disagrees with probe identity")
        service_ips.add(probe["service_ip"])
        frozen_logs[phase] = observer_raw
        # Don't include post-recovery logs: the agent must not peek into
        # the future when explaining the incident under diagnosis.
        if phase in ("before", "during"):
            observations.append({
                "evidence_id": f"np-{phase}-observer",
                "tool": "kubernetes.get_logs",
                "text": (
                    f"phase={phase}; dns_ok=true; "
                    f"name_http_status={probe['name_http_status']}; "
                    "direct_http_attempts="
                    + ",".join(str(x) for x in probe["direct_http_attempts"])
                ),
            })
    if len(service_ips) != 1:
        raise ValueError("probe Service IP drift across phases")

    row = {
        "schema_version": SCHEMA,
        "episode_id": output_id,
        "fault_family": family,
        "split": approval["split"],
        "alert": "Client checkout-api HTTP failure while DNS remains healthy",
        "observations": observations,
        "oracle": {
            "answerable": False,
            "root_cause_id": "unknown",
            "required_evidence_ids": [],
        },
    }
    ep = _decode_episode(row)
    record = (json.dumps(row, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")) + "\n").encode("utf-8")
    # Abort on malformed or overbudget payload before create-only output.
    if len(record) > 32 * 1024:
        raise ValueError("lab candidate exceeds episode budget")
    with Path(output).open("xb") as stream:
        stream.write(record)
    return {
        "schema_version": "sre.grpo.lab-candidate-receipt/v1",
        "source_episode_id": source_id,
        "episode_id": ep.episode_id,
        "approval_sha256": approval_sha,
        "source_episode_sha256": episode_sha,
        "source_evaluation_sha256": evaluation_sha,
        "output_sha256": _digest(record),
        "source_classification": "unverified-lab-candidate",
        "lab_claim_authenticated": False,
        "training_admission_authorized": False,
        "production_causality_verified": False,
    }
