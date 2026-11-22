"""Runtime LoRA effect probe contracts (synthetic metrics, never GPU proof)."""

import math
from types import SimpleNamespace

import pytest

from agentic_aiops.grpo_adapter_effect import (
    validate_local_effect_observation, validate_local_effect_receipt,
)


def good_status():
    return SimpleNamespace(
        enabled=True, active_adapters=["default"], merged_adapters=[],
        peft_types={"default": "LORA"}, num_adapter_layers=1,
        trainable_params=0,
    )


def observe(**changes):
    args = dict(
        prompt_sha256="a"*64, vocab_size=128,
        max_abs_delta=0.125, max_abs_base=12.0,
        enabled_finite=True, disabled_finite=True,
        status_after=good_status(),
    )
    args.update(changes)
    return validate_local_effect_observation(**args)


def test_effective_loaded_adapter_produces_local_only_limited_receipt():
    receipt = observe()
    assert receipt["schema_version"] == "sre.grpo.local-adapter-effect/v1"
    assert receipt["local_forward_effect_observed"] is True
    assert receipt["max_abs_logit_delta"] == 0.125
    assert receipt["normalized_logit_delta"] > 1e-5
    assert receipt["model_runtime_independently_verified"] is False
    assert receipt["superiority_claim_authorized"] is False
    assert receipt["production_eligible"] is False


@pytest.mark.parametrize("value", [0.0, 1e-12, 1e-8])
def test_zero_or_subthreshold_logit_delta_rejected(value):
    with pytest.raises(ValueError, match="no observable adapter effect"):
        observe(max_abs_delta=value)


@pytest.mark.parametrize("field,value", [
    ("max_abs_delta", math.nan),
    ("max_abs_delta", math.inf),
    ("max_abs_base", math.inf),
    ("max_abs_base", -1.0),
    ("max_abs_delta", -1.0),
    ("max_abs_base", True),
    ("vocab_size", 0),
    ("vocab_size", 300001),
    ("vocab_size", True),
    ("enabled_finite", False),
    ("disabled_finite", False),
    ("prompt_sha256", "main"),
])
def test_bad_probe_metrics_or_nonfinite_logits_fail_closed(field, value):
    with pytest.raises(ValueError, match="probe"):
        observe(**{field: value})


@pytest.mark.parametrize("change", [
    {"enabled": False},
    {"active_adapters": []},
    {"merged_adapters": ["default"]},
    {"trainable_params": 1},
])
def test_adapter_must_remain_enabled_unmerged_and_frozen_after_disable_context(change):
    after = good_status()
    for key, value in change.items():
        setattr(after, key, value)
    with pytest.raises(ValueError, match="adapter status"):
        observe(status_after=after)


def test_only_exact_recomputable_local_effect_receipt_is_allowed():
    report = observe()
    assert validate_local_effect_receipt(report) == report
    for name, value in [
        ("max_abs_logit_delta", 0.0),
        ("max_abs_base_logit", -1.0),
        ("normalized_logit_delta", 1.0),
        ("normalized_threshold", 0.0),
        ("local_forward_effect_observed", False),
        ("model_runtime_independently_verified", True),
        ("model_attribution_verified", True),
        ("superiority_claim_authorized", True),
        ("production_eligible", True),
    ]:
        with pytest.raises(ValueError, match="local effect|probe"):
            validate_local_effect_receipt({**report, name: value})
