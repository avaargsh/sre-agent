"""Fail-closed local model-forward effect probe for frozen LoRA adapters.

This is only same-process LAB observation. It is neither independent GPU
attestation nor evidence that SRE diagnosis improves on blind holdouts.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MIN_NORMALIZED_DELTA = 1e-5
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
        "normalized_logit_delta": round(normalized, 9),
        "normalized_threshold": _MIN_NORMALIZED_DELTA,
        "local_forward_effect_observed": True,
        "model_runtime_independently_verified": False,
        "model_attribution_verified": False,
        "superiority_claim_authorized": False,
        "production_eligible": False,
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
    status_after = get_model_status(model)
    if enabled.shape != disabled.shape or len(enabled.shape) != 1:
        raise ValueError("invalid probe output tensor shape")
    if not _status_ok(status_after):
        raise ValueError("adapter status changed or adapter was disabled/unfrozen")
    good_enabled = bool(torch.isfinite(enabled).all().item())
    good_disabled = bool(torch.isfinite(disabled).all().item())
    if not good_enabled or not good_disabled:
        raise ValueError("invalid probe nonfinite enabled/disabled logits")

    return validate_local_effect_observation(
        prompt_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        vocab_size=int(enabled.shape[0]),
        max_abs_delta=float((enabled - disabled).abs().amax().item()),
        max_abs_base=float(disabled.abs().amax().item()),
        enabled_finite=good_enabled, disabled_finite=good_disabled,
        status_after=status_after,
    )
