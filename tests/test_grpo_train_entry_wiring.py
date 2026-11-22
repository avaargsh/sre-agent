"""Run the real training CLI with injectable CPU-only stand-ins.

These tests validate call wiring, not real TRL, CUDA, model identity, or GPU.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks/grpo/synthetic-episodes.jsonl"
MODEL_REV = "a" * 40


class FakeTensor:
    def __init__(self):
        self.content = b"before"
        self.requires_grad = True
        self.shape = (2, 2)
        self.dtype = "torch.bfloat16"

    def numel(self):
        return 4

    def detach(self):
        return self

    def cpu(self):
        return self

    def contiguous(self):
        return self

    def view(self, dtype):
        return self

    def numpy(self):
        return self

    def tobytes(self):
        return self.content


class FakeModel:
    def __init__(self):
        self.param = FakeTensor()
        self.device = None

    def to(self, device):
        self.device = device
        return self

    def named_parameters(self):
        return iter([
            ("model.layers.0.q_proj.lora_A.default.weight", self.param),
        ])


def install_stubs(monkeypatch, *, change):
    state = {"saved": False, "model_revision": None, "tokenizer_revision": None}
    fake_model = FakeModel()

    torch = types.ModuleType("torch")
    torch.uint8 = "torch.uint8"
    torch.bfloat16 = "torch.bfloat16"
    torch.float16 = "torch.float16"
    torch.manual_seed = lambda seed: None
    torch.cuda = types.SimpleNamespace(
        is_available=lambda: True,
        is_bf16_supported=lambda: True,
        get_device_name=lambda device: "FAKE GPU -- NOT HARDWARE EVIDENCE",
    )

    class Tokenizer:
        @classmethod
        def from_pretrained(cls, model, *, revision, trust_remote_code):
            assert model == "Qwen/Qwen3-0.6B"
            assert trust_remote_code is False
            state["tokenizer_revision"] = revision
            return cls()

        def apply_chat_template(self, messages, **kw):
            assert kw["enable_thinking"] is False
            return "[chat]" + messages[0]["content"] + "[assistant]"

        def __call__(self, text, **kw):
            return {"input_ids": text.split()}

    class AutoModel:
        @classmethod
        def from_pretrained(cls, name, *, revision, trust_remote_code, dtype):
            assert name == "Qwen/Qwen3-0.6B"
            assert trust_remote_code is False
            assert dtype == torch.bfloat16
            state["model_revision"] = revision
            return fake_model

    transformers = types.ModuleType("transformers")
    transformers.AutoTokenizer = Tokenizer
    transformers.AutoModelForCausalLM = AutoModel
    datasets = types.ModuleType("datasets")
    datasets.Dataset = types.SimpleNamespace(from_list=lambda rows: rows)
    peft = types.ModuleType("peft")
    peft.LoraConfig = lambda **kw: kw
    trl = types.ModuleType("trl")
    trl.GRPOConfig = lambda **kw: kw

    class FakeGRPOTrainer:
        def __init__(self, *, model, args, train_dataset, processing_class,
                     reward_funcs, peft_config):
            assert model is fake_model
            assert model.device == "cuda"
            assert len(train_dataset) == 1
            assert callable(reward_funcs)
            assert peft_config["task_type"] == "CAUSAL_LM"
            self.model = model
            self.state = types.SimpleNamespace(global_step=0)

        def train(self):
            self.state.global_step = 1
            if change:
                fake_model.param.content = b"after"

        def save_model(self):
            state["saved"] = True

    trl.GRPOTrainer = FakeGRPOTrainer
    for name, module in (
        ("torch", torch), ("transformers", transformers),
        ("datasets", datasets), ("peft", peft), ("trl", trl),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    import importlib.metadata
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "CPU_FAKE")
    return state


def run_entry(monkeypatch, output):
    spec = importlib.util.spec_from_file_location(
        "sre_grpo_training_entry_for_test", ROOT / "scripts/train_sre_grpo.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [
        "train_sre_grpo.py", "--execute", "--lab-only", "--allow-tiny-lab",
        "--dataset", str(DATASET), "--model", "Qwen/Qwen3-0.6B",
        "--model-revision", MODEL_REV, "--output-dir", str(output),
    ])
    return module.main()


def test_entry_loads_same_pinned_model_and_records_only_local_delta(
    monkeypatch, tmp_path
):
    state = install_stubs(monkeypatch, change=True)
    output = tmp_path / "new-run"
    run_entry(monkeypatch, output)
    assert state["saved"] is True
    assert state["model_revision"] == MODEL_REV
    assert state["tokenizer_revision"] == MODEL_REV

    initial = json.loads((output / "sre-grpo-run-manifest.json").read_text())
    evidence = json.loads((output / "sre-grpo-local-lora-delta.json").read_text())
    assert initial["training_status"] == "started_not_verified"
    assert initial["dataset_sha256"] == evidence["dataset_sha256"]
    assert initial["model_revision"] == MODEL_REV
    assert evidence["model_runtime_independently_verified"] is False
    assert evidence["training_admission_authorized"] is False
    assert evidence["production_eligible"] is False
    assert evidence["local_lora_update"]["local_lora_changed"] is True
    assert evidence["local_lora_update"]["global_step"] == 1


def test_entry_never_saves_unmodified_adapter_as_trained(
    monkeypatch, tmp_path
):
    state = install_stubs(monkeypatch, change=False)
    output = tmp_path / "failed-run"
    with pytest.raises(ValueError, match="unchanged"):
        run_entry(monkeypatch, output)
    assert state["saved"] is False
    assert (output / "sre-grpo-run-manifest.json").exists()
    assert not (output / "sre-grpo-local-lora-delta.json").exists()
