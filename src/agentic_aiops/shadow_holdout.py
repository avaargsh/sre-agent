"""LAB-only loopback OpenAI-compatible capture. No Oracle or tool execution."""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import time
from pathlib import Path

from .grpo_import import _verify_pin
from .secure_file import read_pinned_regular, publish_create_only_pair
from .grpo_holdout_projection import (
    _MAX_CASES, _MAX_FILE_BYTES, _MAX_PROMPT_BYTES,
    _validate_paths, _encode_jsonl,
)
from .grpo_training import _fields, _id, _strict_json, _jsonl_lines

_MAX_RESPONSE = 1024 * 1024


def _read_pinned_projection(path, expected_sha256):
    """Pin exact bytes from a bounded regular inode without following path links.

    Every parent component and the final file are opened without following
    symbolic links. A content hash is not issuer authentication and does not
    authorize a data source by itself.
    """
    raw, _identity = read_pinned_regular(
        path, limit=_MAX_FILE_BYTES, label="projection",
    )
    digest = _verify_pin(raw, expected_sha256, "prompts_sha256")
    return raw, digest


def request_local_completion(base_url, payload, *, timeout):
    # Literal loopback only: no redirects, DNS, proxy or credentials.
    match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})/v1", base_url)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise ValueError("require explicit http://127.0.0.1:PORT/v1")
    if not 0 < timeout <= 600:
        raise ValueError("invalid timeout")
    conn = http.client.HTTPConnection("127.0.0.1", int(match.group(1)), timeout=timeout)
    try:
        conn.request("POST", "/v1/chat/completions",
                     body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError(f"endpoint returned HTTP {response.status}")
        raw = response.read(_MAX_RESPONSE + 1)
        if not raw or len(raw) > _MAX_RESPONSE:
            raise ValueError("empty or oversized endpoint response")
        if response.length is not None and response.length != 0:
            raise ValueError("incomplete endpoint response body")
        return _strict_json(raw.decode("utf-8"))
    except http.client.HTTPException as exc:
        raise ValueError("malformed endpoint HTTP response") from exc
    finally:
        conn.close()


def _usage_count(usage, field):
    value = usage.get(field)
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError("invalid endpoint-reported usage")
    return value


def _publish_capture(output: Path, data: bytes, manifest: Path, report: dict) -> None:
    """Create-only pair through component-pinned parent directory descriptors."""
    receipt = (json.dumps(report, ensure_ascii=False, sort_keys=True,
                          indent=2) + "\n").encode("utf-8")
    publish_create_only_pair(output, data, manifest, receipt)


def capture_shadow_holdout(
    prompts, *, expected_prompts_sha256, output, manifest, model,
    revision, engine, quantization, max_tokens, seed, sample,
):
    """Capture exact projected prompts once, preserving raw candidate content.

    A complete run is required. Transport/schema errors abort publication;
    malformed textual diagnoses are retained for the independent scorer.
    Metadata is operator/endpoint-reported, not an authenticated model receipt.
    """
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,160}", model):
        raise ValueError("explicit served model ID required")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("full lowercase model revision required")
    if any(not isinstance(v, str) or not v.strip() or len(v) > 160
           for v in (engine, quantization)):
        raise ValueError("explicit engine and quantization required")
    if type(max_tokens) is not int or not 32 <= max_tokens <= 4096:
        raise ValueError("max_tokens must be 32-4096")
    if type(seed) is not int or not 0 <= seed <= 2**31 - _MAX_CASES:
        raise ValueError("invalid seed")
    _validate_paths(prompts, output, manifest)
    raw, digest = _read_pinned_projection(prompts, expected_prompts_sha256)
    lines = _jsonl_lines(raw.decode("utf-8"))
    if not 1 <= len(lines) <= _MAX_CASES:
        raise ValueError("invalid holdout case count")
    rows = []
    seen = set()
    for line in lines:
        row = _fields(_strict_json(line), {"episode_id", "prompt"}, "shadow prompt")
        eid = _id(row["episode_id"], "episode_id")
        prompt = row["prompt"]
        if eid in seen or type(prompt) is not str or not prompt.strip():
            raise ValueError("duplicate ID or invalid prompt")
        if len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES:
            raise ValueError("oversized prompt")
        seen.add(eid)
        rows.append((eid, prompt))

    predictions = []
    cases = []
    for index, (eid, prompt) in enumerate(rows):
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
                   "temperature": 0, "max_tokens": max_tokens,
                   "seed": seed + index, "stream": False}
        start = time.monotonic_ns()
        result = sample(payload)
        elapsed = (time.monotonic_ns() - start) / 1_000_000
        if type(result) is not dict or result.get("model") != model:
            raise ValueError("response model mismatch")
        choices = result.get("choices")
        if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
            raise ValueError("expected exactly one choice")
        choice = choices[0]
        message = choice.get("message")
        finish = choice.get("finish_reason")
        if (type(message) is not dict or finish != "stop" or
                "tool_calls" in message or "function_call" in message or
                ("role" in message and message["role"] != "assistant")):
            raise ValueError("unexpected non-text or incomplete response")
        completion = message.get("content")
        if type(completion) is not str or len(completion.encode("utf-8")) > 8192:
            raise ValueError("invalid or oversized raw completion")
        usage = result.get("usage")
        if usage is None:
            usage = {}
        if type(usage) is not dict:
            raise ValueError("invalid endpoint-reported usage")
        predictions.append({"episode_id": eid, "completion": completion})
        cases.append({"episode_id": eid, "finish_reason": finish,
                      "latency_ms": round(elapsed, 3),
                      "prompt_tokens": _usage_count(usage, "prompt_tokens"),
                      "completion_tokens": _usage_count(usage, "completion_tokens")})
    data = _encode_jsonl(predictions)
    report = {"schema_version": "sre.shadow.holdout-capture/v1",
              "prompts_sha256": digest, "predictions_sha256": hashlib.sha256(data).hexdigest(),
              "model": model, "claimed_revision": revision, "claimed_engine": engine,
              "claimed_quantization": quantization, "seed": seed, "max_tokens": max_tokens,
              "temperature": 0, "cases": cases,
              "usage_source": "ENDPOINT_REPORTED", "model_runtime_verified": False,
              "model_attribution_verified": False, "production_eligible": False,
              "superiority_claim_authorized": False}
    _publish_capture(Path(output), data, Path(manifest), report)
    return report
