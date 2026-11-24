"""CPU-only Oracle-free Holdout projection and independent read-only replay.

The data-owner process handles private Oracle-bearing Episodes and publishes
only (episode_id, prompt) projections. The separate model runner must never
read the Oracle. Exact SHA pins prove byte consistency, not source authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from .grpo_import import _verify_pin
from .grpo_training import (
    _fields, _strict_json, build_prompt, load_episodes_bytes,
)
from .secure_file import read_pinned_regular

_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_CASES = 2048
_MAX_PROMPT_BYTES = 16 * 1024


def _validate_paths(source: str | Path, output: str | Path, manifest: str | Path) -> None:
    """Reject aliases/overwrites before allocating model resources."""
    paths = [Path(source).resolve(), Path(output).resolve(), Path(manifest).resolve()]
    if len(set(paths)) != 3:
        raise ValueError("source, output and manifest paths must be distinct")
    for target in (Path(output), Path(manifest)):
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"output already exists: {target}")


def _encode_jsonl(rows: list[dict[str, str]]) -> bytes:
    raw = b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )
    if not 0 < len(raw) <= _MAX_FILE_BYTES:
        raise ValueError("holdout JSONL empty or oversized")
    return raw


def _stage_bytes(final: Path, payload: bytes) -> Path:
    """Write and fsync an exclusive, unpublished staging inode."""
    stage = final.with_name(".sre-grpo-" + uuid.uuid4().hex + ".stage")
    try:
        with stage.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        stage.unlink(missing_ok=True)
        raise
    return stage


def _owned_path(target: Path, stage: Path) -> bool:
    """Avoid deleting a concurrent replacement on rollback."""
    try:
        a = os.lstat(target)
        b = os.lstat(stage)
        return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    except FileNotFoundError:
        return False


def _publish_pair(output: Path, raw: bytes, manifest: Path, receipt: dict[str, Any]) -> None:
    """Never publish a truncated final file; refuse concurrent destination names.

    The pair is not an atomic two-file transaction. A sudden SIGKILL between
    links can leave an orphan output, but the verifier must reject that orphan.
    """
    record = (json.dumps(receipt, ensure_ascii=False, sort_keys=True,
                         indent=2) + "\n").encode("utf-8")
    staged_output = None
    staged_manifest = None
    try:
        staged_output = _stage_bytes(output, raw)
        staged_manifest = _stage_bytes(manifest, record)
        os.link(staged_output, output)
        try:
            os.link(staged_manifest, manifest)
        except BaseException:
            if _owned_path(output, staged_output):
                output.unlink()
            raise
    finally:
        if staged_output is not None:
            staged_output.unlink(missing_ok=True)
        if staged_manifest is not None:
            staged_manifest.unlink(missing_ok=True)


def project_holdout_prompts(
    dataset: str | Path,
    *,
    expected_dataset_sha256: str,
    split: str = "test",
    output: str | Path,
    manifest: str | Path,
) -> dict[str, Any]:
    """Project only held-out read-only prompts; discard private Oracle objects."""
    if split not in ("test", "validation"):
        raise ValueError("split must be test or validation, never train")
    _validate_paths(dataset, output, manifest)
    raw_dataset, _dataset_identity = read_pinned_regular(
        dataset, limit=_MAX_FILE_BYTES, label="holdout dataset",
    )
    dataset_sha = _verify_pin(
        raw_dataset, expected_dataset_sha256, "dataset_sha256"
    )
    episodes = load_episodes_bytes(raw_dataset)
    chosen = [ep for ep in episodes if ep.split == split]
    if not 1 <= len(chosen) <= _MAX_CASES:
        raise ValueError("holdout case count must be in [1,2048]")
    rows: list[dict[str, str]] = []
    for ep in chosen:
        prompt = build_prompt(ep)
        if not 0 < len(prompt.encode("utf-8")) <= _MAX_PROMPT_BYTES:
            raise ValueError("holdout prompt empty or oversized")
        rows.append({"episode_id": ep.episode_id, "prompt": prompt})
    raw = _encode_jsonl(rows)
    report = {
        "schema_version": "sre.grpo.holdout-projection/v1",
        "dataset_sha256": dataset_sha,
        "prompts_sha256": hashlib.sha256(raw).hexdigest(),
        "split": split,
        "cases": len(rows),
        "oracle_in_projection": False,
        "model_runtime_verified": False,
        "training_admission_authorized": False,
        "source_classification": "UNVERIFIED_HOLDOUT_PROJECTION",
    }
    _publish_pair(Path(output), raw, Path(manifest), report)
    return report



_PROJECTION_FIELDS = {
    "schema_version", "dataset_sha256", "prompts_sha256", "split", "cases",
    "oracle_in_projection", "model_runtime_verified",
    "training_admission_authorized", "source_classification",
}


def verify_holdout_projection(
    dataset: str | Path,
    prompts: str | Path,
    manifest: str | Path,
    *,
    expected_dataset_sha256: str,
    expected_prompts_sha256: str,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    """Independently replay all projected bytes from externally pinned input.

    Requires original private Episode data and both published projection
    artifacts, but does not call a sampler or import GPU/Adapter dependencies.
    All claim fields are exact-match validated; model/issuer proof stays false.
    """
    # Open each artifact once through component-pinned directory descriptors.
    # Distinct path strings are insufficient: reject parent symlinks, final
    # symlinks, special files and hard-link aliases before parsing any bytes.
    identities: set[tuple[int, int]] = set()
    raw_dataset, _ = read_pinned_regular(
        dataset, limit=_MAX_FILE_BYTES, label="holdout dataset",
        identities=identities,
    )
    dataset_sha = _verify_pin(
        raw_dataset, expected_dataset_sha256, "dataset_sha256",
    )
    raw_prompts, _ = read_pinned_regular(
        prompts, limit=_MAX_FILE_BYTES, label="holdout prompts",
        identities=identities,
    )
    prompts_sha = _verify_pin(
        raw_prompts, expected_prompts_sha256, "prompts_sha256",
    )
    raw_manifest, _ = read_pinned_regular(
        manifest, limit=32 * 1024, label="projection manifest",
        identities=identities,
    )
    manifest_sha = _verify_pin(
        raw_manifest, expected_manifest_sha256, "manifest_sha256",
    )
    try:
        report = _fields(
            _strict_json(raw_manifest.decode("utf-8")),
            _PROJECTION_FIELDS, "projection manifest",
        )
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 projection manifest") from exc
    split = report["split"]
    if type(split) is not str or split not in ("test", "validation"):
        raise ValueError("invalid independent holdout split")
    episodes = load_episodes_bytes(raw_dataset)
    chosen = [ep for ep in episodes if ep.split == split]
    if not 1 <= len(chosen) <= _MAX_CASES:
        raise ValueError("holdout case count must be in [1,2048]")
    rows = []
    for ep in chosen:
        prompt = build_prompt(ep)
        if not 0 < len(prompt.encode("utf-8")) <= _MAX_PROMPT_BYTES:
            raise ValueError("empty or oversized recomputed holdout prompt")
        rows.append({"episode_id": ep.episode_id, "prompt": prompt})
    expected_bytes = _encode_jsonl(rows)
    if raw_prompts != expected_bytes:
        raise ValueError("projection does not match recomputed Oracle-free dataset")
    expected_report = {
        "schema_version": "sre.grpo.holdout-projection/v1",
        "dataset_sha256": dataset_sha,
        "prompts_sha256": prompts_sha,
        "split": split,
        "cases": len(rows),
        "oracle_in_projection": False,
        "model_runtime_verified": False,
        "training_admission_authorized": False,
        "source_classification": "UNVERIFIED_HOLDOUT_PROJECTION",
    }
    # Python equates bool with int (True == 1, False == 0). Enforce the
    # exact JSON value types as well as the contents, especially authority
    # booleans and the holdout case count.
    if any(
        type(report[name]) is not type(value) or report[name] != value
        for name, value in expected_report.items()
    ):
        raise ValueError("projection manifest claims differ from recomputed content")
    return {
        "schema_version": "sre.grpo.projection-replay/v1",
        "dataset_sha256": dataset_sha,
        "prompts_sha256": prompts_sha,
        "manifest_sha256": manifest_sha,
        "cases": len(rows),
        "split": split,
        "exact_projection_bytes_verified": True,
        "oracle_free_projection_verified": True,
        "data_issuer_authenticated": False,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "production_eligible": False,
    }
