"""CPU fake GPU+PEFT tests for real Holdout CLI load wiring, not GPU proof."""

import contextlib
import hashlib
import importlib.util
import json
import struct
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


class FakeLoadedTensor:
    def __init__(self, payload, dtype, shape):
        self.payload = payload
        self.dtype = dtype
        self.shape = tuple(shape)

    def detach(self):
        return self

    def cpu(self):
        return self

    def contiguous(self):
        return self

    def view(self, dtype):
        assert dtype == "torch.uint8"
        return self

    def numpy(self):
        return self

    def tobytes(self):
        return self.payload


class FakeScalar:
    def __init__(self, value):
        self.value = value

    def item(self):
        return self.value


class FakeVector:
    def __init__(self, values):
        self.values = values
        self.shape = (len(values),)

    def detach(self):
        return self

    def float(self):
        return self

    def __sub__(self, other):
        return FakeVector([x-y for x,y in zip(self.values, other.values)])

    def abs(self):
        return FakeVector([abs(x) for x in self.values])

    def amax(self):
        return FakeScalar(max(self.values))


class FakeLogits:
    def __init__(self, values):
        self.values = values

    def __getitem__(self, coords):
        assert coords == (0, -1, slice(None))
        return FakeVector(self.values)


class FakeModel:
    def __init__(self, state):
        self.state = state

    def to(self, device):
        assert device == "cuda"
        return self

    def eval(self):
        return self

    def __call__(self, **kwargs):
        assert self.state["adapter_loaded"] is True
        if self.state["disabled"] or self.state["simulate_no_effect"]:
            values = [2.0, 3.0, 4.0]
        elif self.state["simulate_reenable_drift"] and self.state["disable_seen"]:
            values = [2.0, 3.25, 4.0]
        else:
            values = [2.0, 3.1, 4.0]
        return types.SimpleNamespace(logits=FakeLogits(values))

    @contextlib.contextmanager
    def disable_adapter(self):
        self.state["disabled"] = True
        try:
            yield
        finally:
            self.state["disabled"] = False
            self.state["disable_seen"] = True

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
        "loaded_weights": {}, "simulate_missing_weights": False,
        "disabled": False, "simulate_no_effect": False,
        "disable_seen": False, "simulate_reenable_drift": False,
    }
    torch = types.ModuleType("torch")
    torch.uint8 = "torch.uint8"
    torch.bfloat16 = "torch.bfloat16"
    torch.float16 = "torch.float16"
    torch.cuda = types.SimpleNamespace(
        is_available=lambda: True,
        is_bf16_supported=lambda: True,
        manual_seed_all=lambda seed: None,
    )
    torch.manual_seed = lambda seed: None
    torch.inference_mode = contextlib.nullcontext
    torch.isfinite = lambda vector: types.SimpleNamespace(
        all=lambda: FakeScalar(all(
            isinstance(value, (int, float)) and value == value
            for value in vector.values
        ))
    )

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
        def from_pretrained(cls, base, adapter_path, *, is_trainable, local_files_only,
                            autocast_adapter_dtype):
            assert autocast_adapter_dtype is False
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
            raw = (stage / "adapter_model.safetensors").read_bytes()
            header_len = struct.unpack("<Q", raw[:8])[0]
            header = json.loads(raw[8:8+header_len])
            payload = raw[8+header_len:]
            dtypes = {"F16": "torch.float16", "BF16": "torch.bfloat16",
                      "F32": "torch.float32"}
            state["loaded_weights"] = {
                key: FakeLoadedTensor(
                    payload[value["data_offsets"][0]:value["data_offsets"][1]],
                    dtypes[value["dtype"]], value["shape"],
                )
                for key, value in header.items() if key != "__metadata__"
            }
            state["adapter_loaded"] = True
            state["staging_dir"] = stage
            return base

    transformers = types.ModuleType("transformers")
    transformers.AutoModelForCausalLM = AutoModel
    transformers.AutoTokenizer = Tokenizer
    peft = types.ModuleType("peft")
    peft.PeftModel = PeftModel
    peft.get_peft_model_state_dict = (
        lambda model, *, adapter_name, save_embedding_layers:
        {} if state["simulate_missing_weights"] else state["loaded_weights"]
    )
    peft.get_model_status = lambda model: types.SimpleNamespace(
        enabled=True, active_adapters=["default"],
        merged_adapters=[], peft_types={"default": "LORA"},
        num_adapter_layers=1, trainable_params=0,
    )
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
    assert capture["schema_version"] == "sre.grpo.holdout-capture/v4"
    assert capture["local_effect_probe"]["schema_version"] == (
        "sre.grpo.local-adapter-effect/v2"
    )
    assert capture["local_effect_probe"]["forward_reenable_consistent"] is True
    assert capture["local_effect_probe"]["normalized_reenable_delta"] == 0.0
    assert capture["local_effect_probe"]["local_forward_effect_observed"] is True
    assert capture["local_effect_probe"]["normalized_logit_delta"] > 1e-5
    assert capture["local_effect_probe"]["model_runtime_independently_verified"] is False
    assert capture["checkpoint_role"] == "GRPO"
    assert capture["adapter"]["adapter_weights_sha256"] == pins["expected_adapter_weights_sha256"]
    assert capture["model_runtime_verified"] is False
    assert capture["model_attribution_verified"] is False
    prediction_lines = [
        json.loads(x) for x in (tmp_path/"predictions.jsonl").read_text().splitlines()
    ]
    assert len(prediction_lines) == 2
    assert all(x["completion"] == "{invalid raw model response}" for x in prediction_lines)


def test_cli_refuses_noop_peft_loader_before_publishing_predictions(
    tmp_path, monkeypatch
):
    """A mocked PEFT loader that claims success but omits LoRA must fail."""
    adapter_dir, pins = create_adapter(tmp_path)
    _, prompts, _, projected = projection(tmp_path)
    state = fake_runtime(monkeypatch, pins)
    state["simulate_missing_weights"] = True
    spec = importlib.util.spec_from_file_location(
        "grpo_holdout_adapter_noop_test",
        ROOT / "scripts/sample_sre_grpo_holdout.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    prediction = tmp_path / "no-predictions.jsonl"
    manifest = tmp_path / "no-manifest.json"
    monkeypatch.setattr(sys, "argv", [
        "sample_sre_grpo_holdout.py", "--execute", "--lab-only",
        "--checkpoint-role", "GRPO",
        "--prompts", str(prompts),
        "--expected-prompts-sha256", projected["prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--adapter-dir", str(adapter_dir),
        "--expected-adapter-config-sha256", pins["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", pins["expected_adapter_weights_sha256"],
        "--output", str(prediction),
        "--manifest", str(manifest),
    ])
    import pytest
    with pytest.raises(ValueError, match="tensor set"):
        module.main()
    assert state["sampled"] == 0
    assert not prediction.exists()
    assert not manifest.exists()


def test_cli_refuses_frozen_adapter_that_has_no_forward_effect(
    tmp_path, monkeypatch
):
    """Matching bytes + active PEFT do NOT prove LoRA changes logits."""
    adapter_dir, pins = create_adapter(tmp_path)
    _, prompts, _, projected = projection(tmp_path)
    state = fake_runtime(monkeypatch, pins)
    state["simulate_no_effect"] = True
    script = ROOT / "scripts/sample_sre_grpo_holdout.py"
    spec = importlib.util.spec_from_file_location("grpo_no_effect_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    prediction, manifest = tmp_path/"no-effect.jsonl", tmp_path/"no-effect.json"
    monkeypatch.setattr(sys, "argv", [
        "sample_sre_grpo_holdout.py", "--execute", "--lab-only",
        "--checkpoint-role", "GRPO", "--prompts", str(prompts),
        "--expected-prompts-sha256", projected["prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--adapter-dir", str(adapter_dir),
        "--expected-adapter-config-sha256", pins["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", pins["expected_adapter_weights_sha256"],
        "--output", str(prediction), "--manifest", str(manifest),
    ])
    import pytest
    with pytest.raises(ValueError, match="no observable adapter effect"):
        module.main()
    assert state["sampled"] == 0
    assert not prediction.exists() and not manifest.exists()


def test_adapter_logit_drift_after_reenable_refuses_sampling(
    tmp_path, monkeypatch
):
    """A-B can pass even when A again changes; A-B-A must fail."""
    import pytest
    adapter_dir, pins = create_adapter(tmp_path)
    _, prompts, _, projected = projection(tmp_path)
    state = fake_runtime(monkeypatch, pins)
    state["simulate_reenable_drift"] = True
    spec = importlib.util.spec_from_file_location(
        "grpo_forward_drift_cli_test",
        ROOT / "scripts/sample_sre_grpo_holdout.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    predictions = tmp_path / "unsafe-predictions.jsonl"
    manifest = tmp_path / "unsafe-capture.json"
    monkeypatch.setattr(sys, "argv", [
        "sample_sre_grpo_holdout.py", "--execute", "--lab-only",
        "--checkpoint-role", "GRPO", "--prompts", str(prompts),
        "--expected-prompts-sha256", projected["prompts_sha256"],
        "--model", MODEL, "--revision", REV,
        "--adapter-dir", str(adapter_dir),
        "--expected-adapter-config-sha256", pins["expected_adapter_config_sha256"],
        "--expected-adapter-weights-sha256", pins["expected_adapter_weights_sha256"],
        "--output", str(predictions), "--manifest", str(manifest),
    ])
    with pytest.raises(ValueError, match="reenable|drift"):
        module.main()
    assert state["disable_seen"] is True
    assert state["sampled"] == 0
    assert not predictions.exists() and not manifest.exists()
