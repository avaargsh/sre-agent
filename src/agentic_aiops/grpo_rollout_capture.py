"""Offline, Qwen3-only raw GRPO rollout capture; never a training receipt.

The pure capture core receives a sampler callback for isolated CPU contract
tests. The real CLI supplies a locally loaded revision-pinned CUDA model.
The callback does not receive the held-out Oracle or a training reward.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_training import SREEpisode, load_episodes, qwen3_chat_rows

_REPO = re.compile(r"Qwen/Qwen3-[A-Za-z0-9._-]+\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_MAX_GROUPS = 128
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_LINE_BYTES = 128 * 1024
_MAX_COMPLETION_BYTES = 8192


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
    """Reject unpinned inputs, overwrite and invalid config *before* GPU load."""
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
    out = Path(output)
    meta = Path(manifest)
    if len({ds.resolve(), out.resolve(), meta.resolve()}) != 3:
        raise ValueError("dataset, output and manifest paths must differ")
    if out.exists() or out.is_symlink():
        raise FileExistsError(f"output already exists: {out}")
    if meta.exists() or meta.is_symlink():
        raise FileExistsError(f"manifest already exists: {meta}")
    raw = ds.read_bytes()
    digest = _verify_pin(raw, expected_dataset_sha256, "dataset_sha256")
    episodes = load_episodes(ds)
    selected = tuple(ep for ep in episodes if ep.split == "train")
    if not 1 <= len(selected) <= _MAX_GROUPS:
        raise ValueError("train episode count must be in [1,128]")
    if seed + len(selected) * group_size > 2**31:
        raise ValueError("seed range overflows")
    return selected, digest


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

    # A complete capture must be present in memory before writing anything.
    # Both final paths are create-only; if the manifest fails to write, remove
    # this invocation's previously created raw rollout. A crash between the
    # writes can leave an orphan, but not a valid paired capture manifest.
    with Path(output).open("xb") as stream:
        stream.write(raw)
    try:
        with Path(manifest).open("xb") as stream:
            stream.write(manifest_bytes)
    except BaseException:
        Path(output).unlink()
        raise
    return receipt
