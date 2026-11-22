"""CPU fake GPU+PEFT tests for real Holdout CLI load wiring, not GPU proof."""

import contextlib
import hashlib
import importlib.util
import json
import sys
import types
from pathlib import Path

from test_grpo_adapter import create_adapter, MODEL, REV
from test_grpo_holdout_capture import ROOT, projection


class FakeBatch(dict):
    def to(self, device):
        assert device == "cuda"
        return self


class FakeInputIds:
    shape = (1, 2)


class FakeModel:
    def __init__(self, state):
        self.state = state

    def to(self, device):
        assert device == "cuda"
        return self

    def eval(self):
        return self

    def generate(self, **kwargs):
        assert kwargs["do_sample"] is False
        assert kwargs["max_new_tokens"] == 192
        assert self.state["adapter_loaded"] is True
        self.state["sampled"] += 1
        return [[0, 1, 2, 3]]


def fake_runtime(monkeypatch, pins):
    state = {
        "model_revision": None, "tokenizer_revision": None,
        "adapter_loaded": False, "sampled": 0, "staging_dir": None,
    }
    torch = types.ModuleType("torch")
    torch.bfloat16 = "torch.bfloat16"
    torch.float16 = "torch.float16"
    torch.cuda = types.SimpleNamespace(
        is_available=lambda: True,
        is_bf16_supported=lambda: True,
        manual_seed_all=lambda seed: None,
    )
    torch.manual_seed = lambda seed: None
    torch.inference_mode = contextlib.nullcontext

    class Tokenizer:
        eos_token_id = 1

        @classmethod
        def from_pretrained(cls, model, *, revision, trust_remote_code):
            assert model == MODEL
            assert trust_remote_code is False
            state["tokenizer_revision"] = revision
            return cls()

        def apply_chat_template(self, messages, **kw):
            assert kw["enable_thinking"] is False
            return "NO ORACLE: " + messages[0]["content"]

        def __call__(self, text, **kw):
            if kw.get("return_tensors") == "pt":
                return FakeBatch(input_ids=FakeInputIds())
            return {"input_ids": text.split()}

        def decode(self, values, **kw):
            assert values == [2, 3]
            return "{invalid raw model response}"

    class AutoModel:
        @classmethod
        def from_pretrained(cls, model, *, revision, trust_remote_code, dtype):
            assert model == MODEL
            assert trust_remote_code is False
            state["model_revision"] = revision
            return FakeModel(state)

    class PeftModel:
        @classmethod
        def from_pretrained(cls, base, adapter_path, *, is_trainable, local_files_only):
            assert is_trainable is False
            assert local_files_only is True
            assert isinstance(base, FakeModel)
            stage = Path(adapter_path)
            assert stage.is_dir()
            assert hashlib.sha256((stage/"adapter_config.json").read_bytes()).hexdigest() == (
                pins["expected_adapter_config_sha256"]
            )
            assert hashlib.sha256((stage/"adapter_model.safetensors").read_bytes()).hexdigest() == (
                pins["expected_adapter_weights_sha256"]
            )
            assert set(p.name for p in stage.iterdir()) == {
                "adapter_config.json", "adapter_model.safetensors",
            }
            state["adapter_loaded"] = True
            state["staging_dir"] = stage
            return base

    transformers = types.ModuleType("transformers")
    transformers.AutoModelForCausalLM = AutoModel
    transformers.AutoTokenizer = Tokenizer
    peft = types.ModuleType("peft")
    peft.PeftModel = PeftModel
    for name, val in (("torch", torch), ("transformers", transformers), ("peft", peft)):
        monkeypatch.setitem(sys.modules, name, val)
    return state


def test_cli_loads_pinned_grpo_adapter_before_any_holdout_inference(tmp_path, monkeypatch, capsys):
    adapter_dir, pins = create_adapter(tmp_path)
    _, prompts, _, projected = projection(tmp_path)
    state = fake_runtime(monkeypatch, pins)
    script = ROOT / "scripts/sample_sre_grpo_holdout.py"
    spec = importlib.util.spec_from_file_location("grpo_holdout_adapter_cli_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [
        "sample_sre_grpo_holdout.py", "--execute", "--lab-only",
        "--checkpoint-role", "GRPO",
        "--prompts", str(prompts),
        "--expected-prompts-sha256", projected["prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--adapter-dir", str(adapter_dir),
        "--expected-adapter-config-sha256", pins["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", pins["expected_adapter_weights_sha256"],
        "--output", str(tmp_path/"predictions.jsonl"),
        "--manifest", str(tmp_path/"capture.json"),
    ])
    assert module.main() == 0
    assert state["adapter_loaded"] is True
    assert state["sampled"] == 2
    assert state["model_revision"] == state["tokenizer_revision"] == REV
    assert not state["staging_dir"].exists()
    capture = json.loads((tmp_path/"capture.json").read_text())
    assert capture["checkpoint_role"] == "GRPO"
    assert capture["adapter"]["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    assert capture["model_runtime_verified"] is False
    assert capture["model_attribution_verified"] is False
    prediction_lines = [
        json.loads(x) for x in (tmp_path/"predictions.jsonl").read_text().splitlines()
    ]
    assert len(prediction_lines) == 2
    assert all(x["completion"] == "{invalid raw model response}" for x in prediction_lines)
