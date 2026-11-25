# GRPO post-save LoRA tensor link (CPU-only, LAB-only)

Status: **experimental / HOLD**. This verifier checks whether a pinned Safetensors Adapter contains the exact per-tensor bytes claimed by a separately pinned post-training snapshot and local training receipt. It does not authenticate a model, trainer, optimizer step, GPU execution, dataset issuer, or training authorization.

## Evidence flow

```text
claimed in-memory post-step LoRA parameters
        |
        | capture_posttraining_tensor_map(...)
        v
tensor map: runtime name -> PEFT save name, shape, dtype, raw-byte SHA256
        |
        | external reviewer pins exact map bytes
        v
offline CPU verifier <---- externally pinned local training receipt
        |
        +----------------- externally pinned Adapter config + Safetensors
        |
        v
exact tensor-set / shape / dtype / byte comparison
        |
        v
local_saved_weights_equal_claimed_post_snapshot = true
training_execution_independently_verified = false
optimizer_step_independently_verified = false
production_eligible = false
```

The tensor map is producer-supplied evidence. The verifier can detect a mismatch between the map and saved Adapter bytes, but a producer can fabricate both the claimed post-step map and the training receipt. Matching bytes therefore do **not** prove that a training loop ran or that an optimizer changed the weights.

## Input contract

- `tensor_map`: strict JSON manifest `sre.grpo.post-save-tensor-map/v1`, externally pinned by `--expected-tensor-map-sha256`.
- `train_receipt`: strict local receipt `sre.grpo.local-training-receipt/v1`, externally pinned by `--expected-train-receipt-sha256`. It must remain `LAB_ONLY_UNVERIFIED` and all authority flags must be literal `false`.
- `expected_dataset_sha256`: reviewer-supplied digest compared to the receipt. The verifier does not load or authenticate the dataset bytes.
- `adapter_dir`: contains only `adapter_config.json`, `adapter_model.safetensors`, and optional regular `README.md` (at most 64 KiB; not consumed). Config and weight bytes must match their externally supplied SHA256 pins and the declared Qwen3 base model/revision.
- LoRA tensors must form complete A/B pairs, use supported FP16/BF16/FP32 dtypes, and match the Safetensors tensor set, shapes, dtypes, and exact raw bytes.

## Path and parser restrictions

All pinned files are opened as bounded regular files with `O_NOFOLLOW | O_NONBLOCK`, then checked with `fstat` and read through the same descriptor. Every parent directory is walked through `O_DIRECTORY | O_NOFOLLOW` directory descriptors; parent symlinks and `..` traversal are rejected. The Adapter directory itself is opened once and its two required files are read relative to that pinned directory descriptor. Platforms without the required dir-fd/no-follow support fail closed.

The Safetensors header and tensor offsets are validated before byte comparison. No `torch`, PEFT, CUDA, network, or model endpoint is imported or invoked by the verifier CLI.

## Run

```bash
pip install -e '.[dev]'
pytest -q tests/test_grpo_tensor_link.py tests/test_grpo_tensor_link_cli.py

python scripts/verify_sre_grpo_tensor_link.py \
  --tensor-map "$TENSOR_MAP" \
  --expected-tensor-map-sha256 "$TENSOR_MAP_SHA256" \
  --train-receipt "$TRAIN_RECEIPT" \
  --expected-train-receipt-sha256 "$TRAIN_RECEIPT_SHA256" \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --adapter-dir "$ADAPTER_DIR" \
  --expected-adapter-config-sha256 "$ADAPTER_CONFIG_SHA256" \
  --expected-adapter-weights-sha256 "$ADAPTER_WEIGHTS_SHA256" \
  --model "$BASE_MODEL" \
  --revision "$BASE_MODEL_REVISION"
```

Exit code `3` and `UNKNOWN` on stderr mean the pinned evidence could not be safely verified. A successful report means only local content consistency. Keep GPU execution, optimizer-step verification, model attribution, data provenance, and production admission separate and **HOLD** until independently authenticated evidence exists.
