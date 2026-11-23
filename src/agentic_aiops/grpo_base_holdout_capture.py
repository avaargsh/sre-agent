"""Base-only CPU testable Holdout prediction capture from Oracle-free prompts.

Takes a separately pinned projection, never an Episode or Oracle object.
Captures raw invalid answers without filtering. Runtime/model attribution is
NOT independently verified by a caller-supplied sampler/tokenizer callback.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_holdout_projection import (
    _MAX_CASES, _MAX_FILE_BYTES, _MAX_PROMPT_BYTES,
    _validate_paths, _encode_jsonl, _publish_pair,
)
from .grpo_training import _fields, _id, _strict_json, _read_bounded_bytes

_REPO = re.compile(r"Qwen/Qwen3-[A-Za-z0-9._-]+\\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\\Z")
_MAX_LINE_BYTES = 128 * 1024
_MAX_COMPLETION_BYTES = 8192


def validate_holdout_prompts(
    prompts: str | Path,
    *,
    expected_prompts_sha256: str,
    model: str,
    model_revision: str,
    seed: int,
    max_new_tokens: int,
    split: str,
    output: str | Path,
    manifest: str | Path,
) -> tuple[list[dict[str, str]], str]:
    """Read only the Oracle-free projected file. No original dataset access."""
    if split not in ("test", "validation"):
        raise ValueError("split must be test or validation, never train")
    if type(model) is not str or not _REPO.fullmatch(model):
        raise ValueError("model must be an explicit Qwen/Qwen3-* ID")
    if type(model_revision) is not str or not _SHA40.fullmatch(model_revision):
        raise ValueError("model_revision must be a full lowercase 40-digit SHA")
    if type(seed) is not int or not 0 <= seed <= 2**31 - 1:
        raise ValueError("seed must be a nonnegative 31-bit integer")
    if type(max_new_tokens) is not int or not 32 <= max_new_tokens <= 192:
        raise ValueError("max_new_tokens must be 32-192")
    _validate_paths(prompts, output, manifest)
    if Path(prompts).is_symlink() or not Path(prompts).is_file():
        raise ValueError("prompts must be a regular non-symlink file")
    raw = _read_bounded_bytes(
        prompts, limit=_MAX_FILE_BYTES, name="holdout prompts",
    )
    digest = _verify_pin(raw, expected_prompts_sha256, "prompts_sha256")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("prompts not valid UTF-8") from exc
    if not 1 <= len(lines) <= _MAX_CASES:
        raise ValueError("holdout case count must be in [1,2048]")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        if not line.strip() or len(line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise ValueError("blank or oversized holdout prompt line")
        row = _fields(_strict_json(line), {"episode_id", "prompt"}, "holdout prompt")
        eid = _id(row["episode_id"], "episode_id")
        if eid in seen:
            raise ValueError(f"duplicate episode_id in holdout prompts: {eid}")
        seen.add(eid)
        prompt = row["prompt"]
        if (type(prompt) is not str or not prompt.strip()
                or len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES):
            raise ValueError("empty or oversized holdout prompt")
        rows.append({"episode_id": eid, "prompt": prompt})
    if seed + len(rows) - 1 > 2**31 - 1:
        raise ValueError("seed range exceeds bounded integer limit")
    return rows, digest


def capture_base_holdout_predictions(
    prompts: str | Path,
    *,
    expected_prompts_sha256: str,
    output: str | Path,
    manifest: str | Path,
    tokenizer: Any,
    sampler: Callable[[str, int], str],
    model: str,
    model_revision: str,
    split: str = "test",
    seed: int = 42,
    max_new_tokens: int = 192,
) -> dict[str, Any]:
    """Generate every holdout candidate once; do not filter invalid diagnoses.

    This callback gets only the rendered prompt and integer seed; it receives
    no Episode, Oracle, reward result, or dataset path.
    """
    rows, prompts_sha = validate_holdout_prompts(
        prompts, expected_prompts_sha256=expected_prompts_sha256,
        model=model, model_revision=model_revision, seed=seed,
        max_new_tokens=max_new_tokens, split=split,
        output=output, manifest=manifest,
    )
    inputs: list[tuple[str, str]] = []
    for row in rows:
        chat = tokenizer.apply_chat_template(
            [{"role": "user", "content": row["prompt"]}],
            tokenize=False, add_generation_prompt=True, enable_thinking=False,
        )
        if type(chat) is not str or not chat:
            raise ValueError("Qwen3 non-thinking template returned invalid prompt")
        ids = tokenizer(chat, add_special_tokens=False)["input_ids"]
        if not 0 < len(ids) <= 1024:
            raise ValueError("holdout prompt would be truncated")
        inputs.append((row["episode_id"], chat))
    prompt_hash = hashlib.sha256(json.dumps(
        inputs, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()

    results: list[dict[str, str]] = []
    for i, (eid, chat) in enumerate(inputs):
        completion = sampler(chat, seed + i)
        if type(completion) is not str:
            raise ValueError("completion must be raw decoded text")
        try:
            size = len(completion.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("completion invalid Unicode") from exc
        if size > _MAX_COMPLETION_BYTES:
            raise ValueError("completion exceeds 8192-byte budget")
        results.append({"episode_id": eid, "completion": completion})
    raw = _encode_jsonl(results)
    report = {
        "schema_version": "sre.grpo.holdout-capture/v1",
        "source_classification": "UNVERIFIED_MODEL_HOLDOUT_CAPTURE",
        "prompts_sha256": prompts_sha,
        "predictions_sha256": hashlib.sha256(raw).hexdigest(),
        "prompt_sha256": prompt_hash,
        "cases": len(rows),
        "split": split,
        "model": model,
        "model_revision": model_revision,
        "tokenizer_revision": model_revision,
        "seed": seed,
        "max_new_tokens": max_new_tokens,
        "decoding": {"do_sample": False},
        "thinking_disabled": True,
        "oracle_in_sampler_input": False,
        "model_runtime_verified": False,
        "model_attribution_verified": False,
        "superiority_claim_authorized": False,
        "training_admission_authorized": False,
        "production_eligible": False,
    }
    _publish_pair(Path(output), raw, Path(manifest), report)
    return report
