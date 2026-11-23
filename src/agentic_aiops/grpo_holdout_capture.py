"""Oracle-free holdout projection and Qwen3 candidate capture.

Projection consumes private Oracle-bearing JSONL in the data-owner process.
A *separate* sampler is given only the projected (episode_id, prompt) file.
Neither phase authenticates issuer identity, model identity or training quality.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

from .grpo_import import _verify_pin
from .grpo_adapter import validate_adapter_receipt
from .grpo_adapter_effect import validate_local_effect_receipt
from .grpo_rollout_capture import (
    _REPO, _SHA40, _owned_path, _stage_bytes,
)
from .grpo_training import _fields, _id, _strict_json, build_prompt, load_episodes_bytes

_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_CASES = 2048
_MAX_PROMPT_BYTES = 16 * 1024
_MAX_LINE_BYTES = 128 * 1024
_MAX_COMPLETION_BYTES = 8192


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
    raw_dataset = Path(dataset).read_bytes()
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
    raw = Path(prompts).read_bytes()
    if not 0 < len(raw) <= _MAX_FILE_BYTES:
        raise ValueError("prompts empty or oversized")
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


def capture_holdout_predictions(
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
    checkpoint_role: str = "Base",
    adapter_receipt: dict[str, Any] | None = None,
    local_effect_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate every holdout candidate once; do not filter invalid diagnoses.

    This callback gets only the rendered prompt and integer seed; it receives
    no Episode, Oracle, reward result, or dataset path.
    """
    if checkpoint_role not in ("Base", "SFT", "GRPO"):
        raise ValueError("checkpoint_role must be Base, SFT or GRPO")
    if checkpoint_role == "Base" and adapter_receipt is not None:
        raise ValueError("Base checkpoint_role forbids an adapter receipt")
    if checkpoint_role != "Base" and adapter_receipt is None:
        raise ValueError("SFT/GRPO checkpoint_role requires a pinned adapter receipt")
    if adapter_receipt is not None:
        validate_adapter_receipt(
            adapter_receipt, base_model=model, base_revision=model_revision,
        )
    if local_effect_receipt is not None:
        if checkpoint_role == "Base":
            raise ValueError("Base cannot have local effect probe")
        validate_local_effect_receipt(local_effect_receipt)
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
    if checkpoint_role != "Base":
        report["schema_version"] = "sre.grpo.holdout-capture/v2"
        report["checkpoint_role"] = checkpoint_role
        report["adapter"] = adapter_receipt
        if local_effect_receipt is not None:
            effect_version = local_effect_receipt["schema_version"]
            report["schema_version"] = (
                "sre.grpo.holdout-capture/v4"
                if effect_version == "sre.grpo.local-adapter-effect/v2"
                else "sre.grpo.holdout-capture/v3"
            )
            report["local_effect_probe"] = local_effect_receipt
    _publish_pair(Path(output), raw, Path(manifest), report)
    return report
