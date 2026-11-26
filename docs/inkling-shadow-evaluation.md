# Inkling 2 Mini shadow evaluation (LAB-only)

Status: implementation proposal, NOT a measured model benchmark or production release. Current main base `5de0398bf3c8b56da653731bef92846771b57304`. The public synthetic Episode fixture has one unanswerable test case; smoke only. The Qwen3-specific capture and GRPO Draft #11 are unchanged.

## Reproducible workflow

Use the official model and serving instructions:
- https://huggingface.co/thinkingmachines/Inkling-2-Mini
- https://recipes.vllm.ai/thinkingmachines/Inkling-2-Mini

Pin the real model revision, serving image digest, quantization, engine configuration, hardware, chat template and decode settings out of band. Bind the lab endpoint to loopback, without production tools or credentials. The CLI deliberately accepts only literal loopback and no redirects/proxy. The local server must itself be trusted and isolated; this client does not attest its model identity or egress behavior. A remote/cloud comparison requires a separately approved, sanitized capture by the data owner, not automatic transmission of private incident data.

1. Reviewer freezes a fault-family-separated validation/test dataset, independently supplies its SHA256, and runs the Oracle-free projection and replay verifier. Projection and replay open the dataset, prompt file and manifest through component-wise no-follow directory descriptors, require bounded regular inodes, and reject hard-link aliases before parsing. Pass only the approved prompts and their pin to the isolated runner.
2. Capture the candidate once for every case, preserving malformed textual completions. Before contacting a model, open the reviewer-pinned projection once through component-wise `O_DIRECTORY|O_NOFOLLOW` parent traversal and a final `O_NOFOLLOW|O_NONBLOCK` descriptor; require a bounded regular inode through `fstat`, and hash/parse exactly the bytes from that file descriptor. Reject parent/final symlinks, `..` traversal and FIFO/special-file inputs, even if a stale pathname check suggested an approved regular file. SHA256 is byte consistency only, not issuer or reviewer authentication. An HTTP error, a length-truncated response (`finish_reason=length`), explicit tool-call fields (even empty), a missing/non-assistant role, extra message fields (including refusal/audio/tool metadata), a missing case or an invalid model response aborts publication of the entire run; no fallback or silent retry. Incomplete captures must not enter scoring.
3. Independently freeze both predictions files and compare them against the same private dataset. The paired comparison CLI opens all three pinned files once with component-wise no-follow parent traversal and a final `O_NOFOLLOW|O_NONBLOCK` descriptor, requires bounded regular inodes via `fstat`, rejects duplicate inodes, then verifies the exact opened bytes before scoring. No stale `is_symlink`/`is_file` pathname check is treated as authority; parent/final symlinks, `..` traversal, FIFO and special-file inputs must fail closed. The existing scorer uses exact evidence-gated reward and proper abstention, not model-reported reward.
4. Review the capture manifest (per-case elapsed request time, finish reason and endpoint-reported usage); length-truncated output now aborts publication entirely; no result may be scored or promoted from such a run. Manifest labels and raw-file pins do not authenticate the runtime. Raw API envelopes and independently verified runtime attribution remain future work.
5. Capture outputs are created under component-wise no-follow parent directory descriptors with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, and `fsync`; the manifest is created last as the completion marker. Existing output names are never overwritten. If manifest creation fails, a prediction-only orphan may remain and must not be treated as a complete capture; consumers require and independently pin both files.

```bash
python scripts/project_sre_grpo_holdout.py \
  --dataset "$DATASET" --expected-dataset-sha256 "$DATASET_SHA" \
  --split test --output "$PROMPTS" --manifest "$PROJECTION"

python scripts/verify_sre_grpo_projection.py \
  --dataset "$DATASET" --prompts "$PROMPTS" --manifest "$PROJECTION" \
  --expected-dataset-sha256 "$DATASET_SHA" \
  --expected-prompts-sha256 "$PROMPTS_SHA" \
  --expected-manifest-sha256 "$PROJECTION_SHA"

python scripts/sample_sre_shadow_holdout.py --execute --lab-only \
  --prompts "$PROMPTS" --expected-prompts-sha256 "$PROMPTS_SHA" \
  --base-url http://127.0.0.1:8000/v1 \
  --model thinkingmachines/Inkling-2-Mini --revision "$MODEL_SHA" \
  --engine "$ENGINE" --quantization "$QUANTIZATION" --seed 42 --max-tokens 512 \
  --output "$INKLING" --manifest "$CAPTURE"

python scripts/compare_sre_shadow_holdout.py \
  --dataset "$DATASET" --dataset-sha256 "$DATASET_SHA" \
  --inkling "$INKLING" --inkling-sha256 "$INKLING_SHA" \
  --cloud "$CLOUD" --cloud-sha256 "$CLOUD_SHA" --split test
```

All pins must come from independent review, not from self-approval by the runner. Output paths must be new. Cloud predictions must have exactly the same episode IDs and raw completion format. The comparison intentionally always returns admission HOLD; zero exit means descriptive scoring completed, not a release pass.

## Expansion and pre-registered gates

| Task | Data and deterministic grade |
| --- | --- |
| RCA | Existing Episode/Oracle plus independently reviewed kind faults, conflicting/stale evidence, OOM, DNS, selector, CrashLoop and GPU scenarios when available. |
| Evidence | Existing Go evidence verifier; mutation, nonexistent refs, scope drift and missing observations must remain fail closed. Model cannot override verifier. |
| Tools | Inventory existing replay fixtures, add allowlisted read-only tool argument/scope and injection cases; evaluate native tool calls separately (current runner is text-only). |
| SQL | Inventory existing suite; if owned by data-agent, import reviewed version-pinned sanitized cases only. Check execution results on disposable read-only DB, unsafe SQL denied. No claim SQL suite already exists in sre-agent. |

Provisional acceptance design: at least 100 independent reviewed cases per route class as an initial target (increase based on statistical power), paired confidence interval for noninferiority margin 5 percentage points, correct abstention >=95%, zero observed unauthorized actions or fabricated evidence accepted by deterministic gates, latency/cost benefit. Pre-register final thresholds and sample size before opening blind test results. Three repeat runs where practical; preserve all failures. No model accuracy or latency measured here. Compare full workflow cost, including fallback, hardware, utilization and verification, not token prices alone. Any incomplete/unauthenticated result remains HOLD. No production writes or automatic route changes. Final acceptance requires independent review.

`pytest -q tests/test_shadow_holdout.py` then full Python/Go CI on exact HEAD. Mock tests prove interface behavior only, not an Inkling run.
