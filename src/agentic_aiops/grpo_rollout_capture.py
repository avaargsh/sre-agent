"""Offline, Qwen3-only raw GRPO rollout capture; never a training receipt.

The pure capture core receives a sampler callback for isolated CPU contract
tests. The real CLI supplies a locally loaded revision-pinned CUDA model.
The callback does not receive the held-out Oracle or a training reward.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_training import SREEpisode, _MAX_FILE_BYTES, load_episodes_bytes, qwen3_chat_rows

_REPO = re.compile(r"Qwen/Qwen3-[A-Za-z0-9._-]+\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_MAX_GROUPS = 128
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_LINE_BYTES = 128 * 1024
_MAX_COMPLETION_BYTES = 8192


def validate_capture_inputs(
    dataset: str | Path,
    *,
    expected_dataset_sha256: str,
    model: str,
    model_revision: str,
    group_size: int,
    seed: int,
    max_new_tokens: int,
) -> tuple[tuple[SREEpisode, ...], str]:
    """Validate pinned dataset and bounded sampler config without output paths."""
    if type(model) is not str or not _REPO.fullmatch(model):
        raise ValueError("model must be an explicit Qwen/Qwen3-* repository ID")
    if type(model_revision) is not str or not _SHA40.fullmatch(model_revision):
        raise ValueError("model_revision must be a pinned lowercase 40-character commit")
    if type(group_size) is not int or not 2 <= group_size <= 64:
        raise ValueError("group_size must be in [2,64]")
    if type(seed) is not int or not 0 <= seed <= 2**31 - 1:
        raise ValueError("seed must fit a nonnegative 31-bit integer")
    if type(max_new_tokens) is not int or not 32 <= max_new_tokens <= 192:
        raise ValueError("max_new_tokens must be in [32,192]")
    ds = Path(dataset)
    # Read the SAME bounded regular inode for both the out-of-band pin and
    # parser. Unbounded Path.read_bytes can exhaust memory; it can also follow
    # a mutable symlink or block indefinitely on a substituted FIFO.
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("secure bounded dataset admission unavailable")
    fd = os.open(ds, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= _MAX_FILE_BYTES:
            raise ValueError("dataset must be a bounded regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(_MAX_FILE_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if not raw or len(raw) > _MAX_FILE_BYTES:
        raise ValueError("dataset outside bounded byte budget")
    digest = _verify_pin(raw, expected_dataset_sha256, "dataset_sha256")
    episodes = load_episodes_bytes(raw)
    selected = tuple(ep for ep in episodes if ep.split == "train")
    if not 1 <= len(selected) <= _MAX_GROUPS:
        raise ValueError("train episode count must be in [1,128]")
    if seed + len(selected) * group_size > 2**31:
        raise ValueError("seed range overflows")
    return selected, digest


def prepare_capture(
    dataset: str | Path,
    *,
    expected_dataset_sha256: str,
    model: str,
    model_revision: str,
    group_size: int,
    seed: int,
    max_new_tokens: int,
    output: str | Path,
    manifest: str | Path,
) -> tuple[tuple[SREEpisode, ...], str]:
    """Reject overwrites before GPU model loading; then verify inputs."""
    ds = Path(dataset)
    out = Path(output)
    meta = Path(manifest)
    if len({ds.resolve(), out.resolve(), meta.resolve()}) != 3:
        raise ValueError("dataset, output and manifest paths must differ")
    if out.exists() or out.is_symlink():
        raise FileExistsError(f"output already exists: {out}")
    if meta.exists() or meta.is_symlink():
        raise FileExistsError(f"manifest already exists: {meta}")
    return validate_capture_inputs(
        ds, expected_dataset_sha256=expected_dataset_sha256,
        model=model, model_revision=model_revision,
        group_size=group_size, seed=seed, max_new_tokens=max_new_tokens,
    )


def _stage_bytes(final: Path, payload: bytes) -> Path:
    """Write and sync a private, create-only unpublished staging inode."""
    stage = final.with_name(".sre-grpo-" + uuid.uuid4().hex + ".stage")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure staging unavailable")
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        stage.unlink(missing_ok=True)
        raise
    finally:
        if fd >= 0:
            os.close(fd)
    return stage


def capture_rollout_groups(
    dataset: str | Path,
    *,
    expected_dataset_sha256: str,
    output: str | Path,
    manifest: str | Path,
    tokenizer: Any,
    sampler: Callable[[str, int], str],
    model: str,
    model_revision: str,
    group_size: int = 4,
    seed: int = 42,
    max_new_tokens: int = 192,
) -> dict[str, Any]:
    """Generate all groups before publishing create-only JSONL and manifest.

    The caller is responsible for supplying a genuine model sampler. Merely
    calling this with a mock or synthetic sampler cannot prove model runtime.
    """
    selected, dataset_sha = prepare_capture(
        dataset, expected_dataset_sha256=expected_dataset_sha256,
        model=model, model_revision=model_revision,
        group_size=group_size, seed=seed, max_new_tokens=max_new_tokens,
        output=output, manifest=manifest,
    )
    rows = qwen3_chat_rows(
        tokenizer, selected, max_prompt_tokens=1024,
        max_completion_tokens=max_new_tokens,
    )
    if len(rows) != len(selected):
        raise ValueError("tokenization omitted a train episode")
    prompt_bytes = json.dumps(
        rows, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    prompt_sha = hashlib.sha256(prompt_bytes).hexdigest()

    records: list[bytes] = []
    for group_index, row in enumerate(rows):
        completions: list[str] = []
        for k in range(group_size):
            sample_seed = seed + group_index * group_size + k
            text = sampler(row["prompt"], sample_seed)
            # Do NOT discard malformed JSON, empty text or wrong diagnoses:
            # those are negative model outcomes the independent auditor scores.
            if type(text) is not str:
                raise ValueError("completion must be raw decoded model text")
            try:
                length = len(text.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ValueError("completion has invalid Unicode") from exc
            if length > _MAX_COMPLETION_BYTES:
                raise ValueError("completion exceeds the bounded capture budget")
            completions.append(text)
        packed = (json.dumps({
            "episode_id": row["episode_id"], "completions": completions,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(packed) > _MAX_LINE_BYTES:
            raise ValueError("rollout group exceeds line byte budget")
        records.append(packed)

    raw = b"".join(records)
    if not 0 < len(raw) <= _MAX_OUTPUT_BYTES:
        raise ValueError("rollouts file exceeds bounded audit size")
    rollouts_sha = hashlib.sha256(raw).hexdigest()
    receipt = {
        "schema_version": "sre.grpo.capture-manifest/v1",
        "source_classification": "unverified-model-capture",
        "model": model,
        "model_revision": model_revision,
        "tokenizer_revision": model_revision,
        "dataset_sha256": dataset_sha,
        "rollouts_sha256": rollouts_sha,
        "prompt_sha256": prompt_sha,
        "groups": len(rows),
        "group_size": group_size,
        "sample_count": len(rows) * group_size,
        "seed": seed,
        "max_new_tokens": max_new_tokens,
        "sampling": {"do_sample": True, "temperature": 0.7,
                     "top_p": 0.8, "top_k": 20},
        "thinking_disabled": True,
        "model_runtime_independently_verified": False,
        "training_admission_authorized": False,
        "production_release_authorized": False,
        "oracle_exposed_to_sampler": False,
    }
    manifest_bytes = (json.dumps(
        receipt, sort_keys=True, ensure_ascii=False, indent=2,
    ) + "\n").encode("utf-8")

    # Stage every payload before making a final pathname visible. An
    # interrupted stage cannot publish a truncated final rollout or receipt.
    # Link (not replace) is atomic and refuses competing output names.
    # A crash between links can leave an orphan rollout without a manifest:
    # never admit an orphan; a separate verifier requires both pinned files.
    output_path = Path(output)
    manifest_path = Path(manifest)
    stage_out: Path | None = None
    stage_manifest: Path | None = None
    try:
        stage_out = _stage_bytes(output_path, raw)
        stage_manifest = _stage_bytes(manifest_path, manifest_bytes)
        os.link(stage_out, output_path)
        # Never unlink the first final pathname if the second link fails.
        # The old lstat-then-unlink rollback could erase a concurrent writer
        # that replaces output_path after the inode check. An unpaired raw
        # rollout is not a successful capture: no matching manifest exists.
        os.link(stage_manifest, manifest_path)
    finally:
        if stage_out is not None:
            stage_out.unlink(missing_ok=True)
        if stage_manifest is not None:
            stage_manifest.unlink(missing_ok=True)
    return receipt
