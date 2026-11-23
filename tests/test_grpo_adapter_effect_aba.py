"""A-B-A LoRA probe: reject drift after re-enabling an adapter.

CPU-only metrics; no actual CUDA evidence.
"""

import math
from types import SimpleNamespace

import pytest

from agentic_aiops.grpo_adapter_effect import (
    validate_aba_effect_observation, validate_local_effect_receipt,
)


def status():
    return SimpleNamespace(
        enabled=True, active_adapters=["default"],
        merged_adapters=[], peft_types={"default": "LORA"},
        num_adapter_layers=1, trainable_params=0,
    )


def valid(**overrides):
    values = {
        "prompt_sha256": "b"*64,
        "vocab_size": 128,
        "max_abs_delta": 0.125,
        "max_abs_base": 12.0,
        "max_abs_reenable_delta": 0.0,
        "enabled_finite": True,
        "disabled_finite": True,
        "reenabled_finite": True,
        "status_after": status(),
    }
    values.update(overrides)
    return validate_aba_effect_observation(**values)


def test_identical_reenabled_logits_required_and_observation_is_local_only():
    report = valid()
    assert report["schema_version"] == "sre.grpo.local-adapter-effect/v2"
    assert report["max_abs_logit_delta"] == 0.125
    assert report["max_abs_reenable_delta"] == 0.0
    assert report["normalized_reenable_delta"] == 0.0
    assert report["local_forward_effect_observed"] is True
    assert report["forward_reenable_consistent"] is True
    assert report["model_runtime_independently_verified"] is False
    assert report["model_attribution_verified"] is False
    assert report["production_eligible"] is False
    assert validate_local_effect_receipt(report) == report


@pytest.mark.parametrize("delta", [0.01, 0.1, 1.0])
def test_reenable_drifts_cannot_pass_even_when_adapter_effect_looks_large(delta):
    with pytest.raises(ValueError, match="reenable|drift"):
        valid(max_abs_reenable_delta=delta)


@pytest.mark.parametrize("field,value", [
    ("max_abs_reenable_delta", math.nan),
    ("max_abs_reenable_delta", math.inf),
    ("max_abs_reenable_delta", -1.0),
    ("max_abs_reenable_delta", True),
    ("reenabled_finite", False),
    ("reenabled_finite", 1),
])
def test_numerical_or_finite_reenable_proof_must_be_well_formed(field, value):
    with pytest.raises(ValueError, match="reenable|probe"):
        valid(**{field: value})


def test_rehashed_forged_aba_claims_are_rejected():
    report = valid()
    changed = [
        ("max_abs_reenable_delta", 0.1),
        ("normalized_reenable_delta", 0.25),
        ("reenable_threshold", 1.0),
        ("forward_reenable_consistent", False),
        ("reenabled_finite", False),
        ("model_runtime_independently_verified", True),
    ]
    for field, value in changed:
        with pytest.raises(ValueError, match="local effect|reenable|probe"):
            validate_local_effect_receipt({**report, field: value})


def test_legacy_v1_receipt_remains_valid_but_not_aba_proof():
    from test_grpo_adapter_effect import observe
    legacy = observe()
    assert legacy["schema_version"] == "sre.grpo.local-adapter-effect/v1"
    assert validate_local_effect_receipt(legacy) == legacy
    with pytest.raises(ValueError, match="local effect|probe"):
        validate_local_effect_receipt({
            **legacy, "forward_reenable_consistent": True,
        })
