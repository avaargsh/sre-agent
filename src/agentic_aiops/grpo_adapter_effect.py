"""Fail-closed local model-forward effect probe for frozen LoRA adapters.

This is only same-process LAB observation. It is neither independent GPU
attestation nor evidence that SRE diagnosis improves on blind holdouts.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from .grpo_training import _fields

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MIN_NORMALIZED_DELTA = 1e-5
_MAX_REENABLE_NORMALIZED_DRIFT = 1e-5
_PROBE = (
    "For a Kubernetes Pod that restarts frequently, what read-only "
    "evidence would you inspect first? Return a short JSON answer."
)


def _status_ok(status: Any) -> bool:
    return (
        getattr(status, "enabled", None) is True
        and getattr(status, "active_adapters", None) == ["default"]
        and getattr(status, "merged_adapters", None) == []
        and getattr(status, "peft_types", None) == {"default": "LORA"}
        and type(getattr(status, "num_adapter_layers", None)) is int
        and status.num_adapter_layers > 0
        and type(getattr(status, "trainable_params", None)) is int
        and status.trainable_params == 0
    )


def validate_local_effect_observation(
    *, prompt_sha256: str, vocab_size: int, max_abs_delta: float,
    max_abs_base: float, enabled_finite: bool, disabled_finite: bool,
    status_after: Any,
) -> dict[str, Any]:
    """Refuse no-op or nonfinite logits and loss of PEFT frozen inference state."""
    if type(prompt_sha256) is not str or not _SHA256.fullmatch(prompt_sha256):
        raise ValueError("invalid probe prompt_sha256")
    if type(vocab_size) is not int or not 1 <= vocab_size <= 300_000:
        raise ValueError("invalid probe vocab_size")
    for value in (max_abs_delta, max_abs_base):
        if (type(value) not in (int, float)
                or not math.isfinite(value) or value < 0):
            raise ValueError("invalid probe nonfinite/negative logits metric")
    if type(enabled_finite) is not bool or type(disabled_finite) is not bool:
        raise ValueError("invalid probe finite flags")
    if not enabled_finite or not disabled_finite:
        raise ValueError("invalid probe nonfinite enabled/disabled logits")
    if not _status_ok(status_after):
        raise ValueError("adapter status changed or adapter was disabled/unfrozen")
    normalized = float(max_abs_delta) / max(1.0, float(max_abs_base))
    if not normalized > _MIN_NORMALIZED_DELTA:
        raise ValueError("no observable adapter effect on fixed probe")
    return {
        "schema_version": "sre.grpo.local-adapter-effect/v1",
        "prompt_sha256": prompt_sha256,
        "vocab_size": vocab_size,
        "max_abs_logit_delta": float(max_abs_delta),
        "max_abs_base_logit": float(max_abs_base),
        "normalized_logit_delta": round(normalized, 9),
        "normalized_threshold": _MIN_NORMALIZED_DELTA,
        "local_forward_effect_observed": True,
        "model_runtime_independently_verified": False,
        "model_attribution_verified": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
    }


def validate_aba_effect_observation(
    *, prompt_sha256: str, vocab_size: int, max_abs_delta: float,
    max_abs_base: float, max_abs_reenable_delta: float,
    enabled_finite: bool, disabled_finite: bool, reenabled_finite: bool,
    status_after: Any,
) -> dict[str, Any]:
    """Fail closed unless enabled-after matches enabled-before.

    A-B can show an apparent effect even when repeated model forward passes
    drift. A-B-A explicitly requires reproducibility upon re-enabling.
    Both thresholds are bounded LAB heuristics, not numerical guarantees.
    """
    if type(reenabled_finite) is not bool or reenabled_finite is not True:
        raise ValueError("invalid probe reenabled finite status")
    if (type(max_abs_reenable_delta) not in (float, int)
            or not math.isfinite(max_abs_reenable_delta)
            or max_abs_reenable_delta < 0):
        raise ValueError("invalid probe reenable logit delta")
    result = validate_local_effect_observation(
        prompt_sha256=prompt_sha256, vocab_size=vocab_size,
        max_abs_delta=max_abs_delta, max_abs_base=max_abs_base,
        enabled_finite=enabled_finite, disabled_finite=disabled_finite,
        status_after=status_after,
    )
    normalized_drift = (
        float(max_abs_reenable_delta)
        / max(1.0, float(max_abs_base))
    )
    if normalized_drift > _MAX_REENABLE_NORMALIZED_DRIFT:
        raise ValueError("LoRA reenable forward-logit drift exceeds LAB limit")
    return {
        **result,
        "schema_version": "sre.grpo.local-adapter-effect/v2",
        "max_abs_reenable_delta": float(max_abs_reenable_delta),
        "normalized_reenable_delta": round(normalized_drift, 9),
        "reenable_threshold": _MAX_REENABLE_NORMALIZED_DRIFT,
        "reenabled_finite": True,
        "forward_reenable_consistent": True,
    }


def probe_loaded_adapter_effect(
    model: Any, tokenizer: Any, *,
    torch: Any, get_model_status: Any,
) -> dict[str, Any]:
    """Run a small identical forward pass with and without the LoRA adapter.

    Uses PEFT's disable_adapter() context manager, and checks PEFT status
    after exiting it because some versions may change requires_grad during
    the enable/disable cycle. Never run an Oracle-bearing prompt in probe.
    """
    if not _status_ok(get_model_status(model)):
        raise ValueError("adapter status invalid before forward probe")
    prompt = tokenizer.apply_chat_template(
        [{"role": "user", "content": _PROBE}],
        tokenize=False, add_generation_prompt=True, enable_thinking=False,
    )
    if type(prompt) is not str or not 0 < len(prompt.encode("utf-8")) <= 4096:
        raise ValueError("invalid probe chat prompt")
    inputs = tokenizer(
        prompt, add_special_tokens=False, return_tensors="pt",
    ).to("cuda")
    count = inputs["input_ids"].shape[-1]
    if type(count) is not int or not 1 <= count <= 128:
        raise ValueError("invalid probe input token count")

    def logits():
        with torch.inference_mode():
            return model(**inputs).logits[0, -1, :].detach().float()

    enabled = logits()
    with model.disable_adapter():
        disabled = logits()
    # Repeat with the adapter re-enabled; A-B alone can confuse
    # nondeterministic forward drift with a causal LoRA contribution.
    reenabled = logits()
    status_after = get_model_status(model)
    if (len(enabled.shape) != 1
            or enabled.shape != disabled.shape
            or enabled.shape != reenabled.shape):
        raise ValueError("invalid probe output tensor shape")
    if not _status_ok(status_after):
        raise ValueError("adapter status changed or adapter was disabled/unfrozen")
    good_enabled = bool(torch.isfinite(enabled).all().item())
    good_disabled = bool(torch.isfinite(disabled).all().item())
    good_reenabled = bool(torch.isfinite(reenabled).all().item())
    if not (good_enabled and good_disabled and good_reenabled):
        raise ValueError("invalid probe nonfinite enabled/disabled/reenabled logits")

    return validate_aba_effect_observation(
        prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        vocab_size=int(enabled.shape[0]),
        max_abs_delta=float((enabled - disabled).abs().amax().item()),
        max_abs_base=float(disabled.abs().amax().item()),
        max_abs_reenable_delta=float((enabled - reenabled).abs().amax().item()),
        enabled_finite=good_enabled, disabled_finite=good_disabled,
        reenabled_finite=good_reenabled,
        status_after=status_after,
    )


_LOCAL_EFFECT_FIELDS = {
    "schema_version", "prompt_sha256", "vocab_size", "max_abs_logit_delta",
    "max_abs_base_logit", "normalized_logit_delta", "normalized_threshold",
    "local_forward_effect_observed", "model_runtime_independently_verified",
    "model_attribution_verified", "superiority_claim_authorized",
    "production_eligible",
}

_LOCAL_EFFECT_FIELDS_V2 = _LOCAL_EFFECT_FIELDS | {
    "max_abs_reenable_delta", "normalized_reenable_delta",
    "reenable_threshold", "reenabled_finite",
    "forward_reenable_consistent",
}


def validate_local_effect_receipt(value: Any) -> dict[str, Any]:
    """Validate a self-reported local effect claim, NOT model attestation.

    Never trust a receipt to establish the model actually ran: it can be
    forged. Bind the exact receipt into the capture manifest and require
    independent model execution evidence before authorizing a claim.
    """
    version = value.get("schema_version") if type(value) is dict else None
    field_set = (
        _LOCAL_EFFECT_FIELDS_V2 if version == "sre.grpo.local-adapter-effect/v2"
        else _LOCAL_EFFECT_FIELDS
    )
    try:
        report = _fields(value, field_set, "local effect probe")
    except ValueError as exc:
        raise ValueError(f"invalid local effect probe fields: {exc}") from exc
    if report["schema_version"] not in (
        "sre.grpo.local-adapter-effect/v1",
        "sre.grpo.local-adapter-effect/v2",
    ):
        raise ValueError("invalid local effect probe schema_version")
    if (type(report["prompt_sha256"]) is not str
            or not _SHA256.fullmatch(report["prompt_sha256"])
            or type(report["vocab_size"]) is not int
            or not 1 <= report["vocab_size"] <= 300_000):
        raise ValueError("invalid local effect probe prompt/vocab")
    delta, base = report["max_abs_logit_delta"], report["max_abs_base_logit"]
    if (type(delta) not in (float, int) or type(base) not in (float, int)
            or not math.isfinite(delta) or not math.isfinite(base)
            or delta < 0 or base < 0):
        raise ValueError("invalid local effect probe nonfinite logits")
    ratio = float(delta) / max(1.0, float(base))
    if not ratio > _MIN_NORMALIZED_DELTA:
        raise ValueError("invalid local effect probe no observable adapter effect")
    if (type(report["normalized_logit_delta"]) not in (float, int)
            or report["normalized_logit_delta"] != round(ratio, 9)
            or type(report["normalized_threshold"]) not in (float, int)
            or report["normalized_threshold"] != _MIN_NORMALIZED_DELTA):
        raise ValueError("invalid local effect probe normalized metrics")
    if report["local_forward_effect_observed"] is not True:
        raise ValueError("invalid local effect probe observed flag")
    for field in ("model_runtime_independently_verified",
                  "model_attribution_verified", "superiority_claim_authorized",
                  "production_eligible"):
        if report[field] is not False:
            raise ValueError(f"invalid local effect probe {field} claim")
    if report["schema_version"] == "sre.grpo.local-adapter-effect/v2":
        reen = report["max_abs_reenable_delta"]
        if (type(reen) not in (int, float) or not math.isfinite(reen)
                or reen < 0):
            raise ValueError("invalid local effect probe reenable delta")
        reen_norm = float(reen) / max(1.0, float(base))
        if (reen_norm > _MAX_REENABLE_NORMALIZED_DRIFT
                or type(report["normalized_reenable_delta"]) not in (int, float)
                or report["normalized_reenable_delta"] != round(reen_norm, 9)
                or type(report["reenable_threshold"]) not in (int, float)
                or report["reenable_threshold"] != _MAX_REENABLE_NORMALIZED_DRIFT
                or report["reenabled_finite"] is not True
                or report["forward_reenable_consistent"] is not True):
            raise ValueError("invalid local effect probe reenable consistency")
    return report
