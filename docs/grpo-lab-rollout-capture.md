# Qwen3 raw rollout capture — experimental LAB ONLY

This slice is extracted from [Draft #11](https://github.com/avaargsh/sre-agent/pull/11) and is intentionally separate from real GRPO optimizer training, production release, cluster writes, and independently authenticated model execution.

## What it does

`scripts/sample_sre_grpo.py` requires explicit `--execute --lab-only`, a pinned lowercase 40-character model revision, a separately obtained SHA-256 pin for a frozen `sre.grpo.episode/v1` JSONL dataset, and a CUDA GPU. The code imports Torch/Transformers **only after** its CPU preflight. A train set with fewer than eight rows requires `--allow-tiny-lab`; that switch is forbidden for eight or more train episodes.

The read-only capture core (`src/agentic_aiops/grpo_rollout_capture.py`) uses exactly the externally SHA-pinned bounded regular dataset bytes for parsing, selects **train only**, renders a Qwen3 non-thinking prompt with the preexisting Episode builder, and invokes a sampler once per unique seed and group position. Missing, malformed, abstaining and wrong raw completions are retained for independent scoring; the capture does **not** select or improve them using an Oracle. The output is a JSONL sequence of `episode_id` + `completions` and a separately linked manifest with dataset/rollout/prompt digests, explicit generation parameters, and `unverified-model-capture` classification.

Source, staging and published outputs have bounded sizes. Input must be a regular no-follow file, never an unbounded `Path.read_bytes` from a symlink or FIFO. Private `0600` staged outputs are `fsync`ed then create-only hard-linked. An interrupted publication **or a manifest creation conflict** leaves an **orphan rollout without a matching manifest**. The publisher intentionally **does not unlink an already published rollout** after a failed manifest link: an `lstat`-then-`unlink` rollback can race with another writer replacing that pathname and destroy their file. A failed capture returns an error, not a valid receipt; the unpaired rollout must be quarantined/handled by the operator and must not be admitted as independently verified evidence. A separate verifier must independently pin and check both output files before trusting any derived score. Only run against an operator-owned private directory.

## Example — isolated lab, never production

```bash
python -m pip install -e '.[capture]'
DATASET=/path/to/approved-frozen-training.jsonl
DATASET_SHA256=<externally_obtained_dataset_sha256>
MODEL_REVISION=<explicit_full_lowercase_40_char_HF_commit>
python scripts/sample_sre_grpo.py \
  --execute --lab-only \
  --dataset "$DATASET" \
  --expected-dataset-sha256 "$DATASET_SHA256" \
  --model 'Qwen/Qwen3-0.6B' \
  --revision "$MODEL_REVISION" \
  --num-generations 4 --seed 42 --max-new-tokens 192 \
  --output /path/to/new/rollouts.jsonl \
  --manifest /path/to/new/capture-manifest.json
```

Use fresh output names inside a controlled private directory. `--allow-tiny-lab` is only for fewer than eight train rows. No CPU fallback is permitted in the real model CLI; CPU-only test doubles exercise the pure capture contract and **cannot prove GPU model execution**. Network/model downloads by a model-loading library are experimental and must be governed by the operator.

## Evidence / trust limitations

- **No provenance attestation:** a 40-character repository commit and SHA-256 hashes describe requested revisions and content integrity; neither authenticates the model artifact, code distribution, tokenizer, runtime or data issuer.
- **No training or optimizer proof:** this slice samples raw completions only. It does not execute TRL GRPO or PEFT training, show LoRA updates, establish reward-hacking resistance, measure blinded Holdout uplift, or authorize training admission.
- **No production or live SRE authority:** only frozen Episode data is read. The manifest explicitly sets `model_runtime_independently_verified=false`, `training_admission_authorized=false` and `production_release_authorized=false`. No Kubernetes credentials or remediation access are provided.
- **Verification pending:** exact-HEAD Python 3.11/3.12 tests, current-main Go race/vet/build, applicable kind evidence, real pinned CUDA runs and independent issuer/security review have **not** been inferred from tests copied from a Draft or a synthetic sampler.

The current branch's deterministic CPU tests verify only parsing, negative-output preservation, no Oracle prompt leakage, input pinning, private output, late-writer non-overwrite and rejection paths. Only independently sourced logs and run identity may support a future promoted result.
