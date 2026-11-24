# SRE Agent SQL holdout (CPU-only, LAB-only)

Status: **experimental / HOLD**. This is an independent descriptive grader for model-proposed SQL, not a database connector or a production tool. It makes no model-identity, dataset-issuer, quality-superiority, routing, or production claims. It does not contact Inkling, Qwen or cloud endpoints.

## Authority boundary

- A data owner prepares a **separate, reviewed** sanitized case artifact containing an in-memory SQLite fixture and private expected rows. The model runner receives only an approved prompt and schema, **never** the expected rows or private Oracle.
- The untrusted model emits a separate `{"case_id":"...","sql":"..."}` JSON prediction. There is no native tool invocation, secret-bearing URL, production database or Kubernetes access.
- An offline scorer receives both independently pinned artifacts. SHA256 proves the submitted bytes match the selected pins; it **does not** authenticate an issuer, reviewer, model runtime or source. Case labels are not provenance attestations.
- The evaluator creates a **new `:memory:`** SQLite database from bounded fixture records. The model cannot choose a database filename. `query_only=ON`, a deny-by-default authorizer, a function allowlist, SQLite size/expression limits and an opcode progress budget constrain its SQL. Only `SELECT` and read-only `WITH` are candidates; write statements, extensions, metadata reads, multi-statements, unsafe functions and runaway queries are rejected. These defenses are only a local lab guardrail, **not** a security boundary for executing arbitrary hostile SQL in the same process; isolate the scorer with OS/container restrictions before processing adversarial inputs.
- A candidate must also produce at least one authorized `SQLITE_READ` dependency on a fixture table to reach the scoring stage. Constant-only expressions, including literal-only CTEs, remain `REJECTED` even if they happen to match the hidden Oracle. This is a **syntactic, compile-time read-dependency check**: it does not prove semantic dependence or authentic source evidence (for example, a constant `SELECT 2 FROM incidents LIMIT 1` can still touch an allowed table). Never interpret this guard as issuer authentication or production-quality evidence verification. Independent, blinded adversarial evaluation remains required.
- Fixture cells must match the declared column type before insertion: `INTEGER` requires a JSON integer, `REAL` a JSON floating-point number (e.g. `2.0`), `TEXT` a JSON string; `null` is accepted for all. No implicit SQLite affinity coercion is allowed, so pinned values such as `"002"` cannot silently become `2`.
- All fixture text cells, private expected rows and candidate SQL must contain valid Unicode scalar values. Escaped lone surrogate code points are invalid input, not an incorrect candidate score; ordinary non-BMP Unicode remains supported.
- Comparisons are **ordered**, type-strict cell equality. This is a deliberate narrow contract: SQL with nondeterministic row order is not rewarded by normalization or silent sorting. Evaluation is descriptive even when results match.
- Any invalid fixture/candidate pin, duplicate JSON key, aliasing inode, symlink or special file produces exit code 3 and no result on stdout. A safely executed but incorrect query yields `COMPLETED` with `exact_result_match=false`. Rejected SQL yields `REJECTED`. Every successful report still has `admission=HOLD` and all authority flags `false`.

## Exact input schema

Trusted/reviewed case file, with one or more in-memory tables, **not** a live database:

```json
{
  "schema_version": "sre.sql.holdout-case/v1",
  "case_id": "lab-example-1",
  "tables": [
    {
      "name": "incidents",
      "columns": [
        {"name": "id", "type": "INTEGER"},
        {"name": "severity", "type": "TEXT"}
      ],
      "rows": [[1, "high"], [2, "low"], [3, "high"]]
    }
  ],
  "expected_rows": [[2]]
}
```

Separate model prediction, with **no expected rows**:

```json
{"case_id":"lab-example-1","sql":"SELECT COUNT(*) FROM incidents WHERE severity = 'high'"}
```

```bash
PYTHONPATH=src python scripts/evaluate_sre_sql_holdout.py \
  --case "$CASE_JSON" --case-sha256 "$REVIEWER_PINNED_CASE_SHA256" \
  --prediction "$PRED_JSON" --prediction-sha256 "$REVIEWER_PINNED_PRED_SHA256"

PYTHONPATH=src python -m pytest -q tests/test_sql_holdout.py
```

Maximums: 128 KiB per input; 4 tables; 12 columns/table; 128 fixture rows/table; 256 result rows; 1 MiB serialized aggregate result payload; 4096 SQL characters. The scorer does **not** attest runtime identity, validate original incident evidence, or decide whether a model-produced SQL statement is authorized against a real DB. Actual production SQL remains outside this module.

## Integration and merge gates

1. Re-run the focused tests and complete repository Python 3.11/3.12 + Go checks against the **exact candidate SHA**. Reject skipped tests or stale SHA evidence.
2. Have a non-author independently review authorizer semantics, data isolation, DoS budgets, malformed JSON and file identity checks; verify no production tool exposure.
3. Freeze real, permissioned, sanitized SQL Holdout cases with lineage, source digests, blind expected results and a separate reviewer. Synthetic fixtures do not count as real incidents or a measured model benchmark.
4. Capture actual Inkling/Qwen/cloud SQL predictions under the same approved prompts, budgets and privacy constraints. Score blindly and compare results and uncertainty. Never auto-route or promote on these descriptive reports.
5. Keep #52, #54 and training #11 merge/authority gates independent. Do not merge this module to bypass non-author approval or missing CI.
