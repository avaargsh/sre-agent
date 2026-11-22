"""CPU-only saved Trainer artifacts -> separate strict PEFT Adapter directory."""

from pathlib import Path

import pytest

from agentic_aiops.grpo_tensor_link import stage_training_saved_adapter
from test_grpo_adapter import MODEL, REV, create_adapter


def test_isolated_adapter_export_ignores_untrusted_root_sidecars(tmp_path):
    source, pins = create_adapter(tmp_path)
    (source/"trainer_state.json").write_text('{"step":2}')
    (source/"optimizer.pt").write_bytes(b"not a trusted adapter")
    target = tmp_path/"isolated-adapter"
    frozen = stage_training_saved_adapter(
        source, target, base_model=MODEL, base_revision=REV,
    )
    assert frozen.receipt["adapter_weights_sha256"] == pins[
        "expected_adapter_weights_sha256"
    ]
    assert sorted(p.name for p in target.iterdir()) == [
        "adapter_config.json", "adapter_model.safetensors",
    ]
    assert (source/"optimizer.pt").read_bytes() == b"not a trusted adapter"


def test_staging_never_overwrites_an_existing_adapter_target(tmp_path):
    source, _ = create_adapter(tmp_path)
    target = tmp_path/"existing"
    target.mkdir()
    (target/"reserved").write_bytes(b"original")
    with pytest.raises(FileExistsError):
        stage_training_saved_adapter(
            source,target,base_model=MODEL,base_revision=REV,
        )
    assert (target/"reserved").read_bytes() == b"original"


@pytest.mark.parametrize("bad", ["adapter_model.safetensors", "adapter_config.json"])
def test_source_symlink_rejected_before_any_isolated_export(tmp_path, bad):
    source, _ = create_adapter(tmp_path)
    moved = tmp_path/"outside"
    (source/bad).rename(moved)
    (source/bad).symlink_to(moved)
    target = tmp_path/"isolated"
    with pytest.raises(ValueError, match="symlink"):
        stage_training_saved_adapter(
            source,target,base_model=MODEL,base_revision=REV,
        )
    assert not target.exists()


def test_corrupt_saved_trainer_safetensors_refused_before_export(tmp_path):
    source, _ = create_adapter(tmp_path)
    (source/"adapter_model.safetensors").write_bytes(b"not-safe-tensors")
    target = tmp_path/"isolated"
    with pytest.raises(ValueError, match="safetensors|LoRA"):
        stage_training_saved_adapter(
            source,target,base_model=MODEL,base_revision=REV,
        )
    assert not target.exists()
