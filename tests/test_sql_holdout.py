"""Synthetic, offline SQL safety contracts; no real database or model claims."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.sql_holdout import evaluate_sql_case

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    return {
        "schema_version": "sre.sql.holdout-case/v1", "case_id": "cpu-1",
        "tables": [{"name": "incidents", "columns": [
            {"name": "id", "type": "INTEGER"},
            {"name": "severity", "type": "TEXT"},
        ], "rows": [[1, "high"], [2, "low"], [3, "high"]]}],
        "expected_rows": [[2]],
    }


def test_correct_select_is_descriptive_and_never_authorizes():
    result = evaluate_sql_case(fixture(), "SELECT COUNT(*) FROM incidents WHERE severity='high'")
    assert result["execution_status"] == "COMPLETED"
    assert result["exact_result_match"] is True
    assert result["admission"] == "HOLD"
    for field in ("data_issuer_authenticated", "model_attribution_verified", "routing_authorized", "production_eligible"):
        assert result[field] is False


def test_wrong_result_does_not_promote():
    result = evaluate_sql_case(fixture(), "SELECT COUNT(*) FROM incidents")
    assert result["execution_status"] == "COMPLETED"
    assert result["exact_result_match"] is False
    assert result["admission"] == "HOLD"


@pytest.mark.parametrize("query", [
    "DELETE FROM incidents", "UPDATE incidents SET severity='low'",
    "DROP TABLE incidents", "PRAGMA database_list", "ATTACH DATABASE '/tmp/x' AS x",
    "SELECT * FROM sqlite_master", "SELECT sqlite_version()",
    "SELECT load_extension('x')", "SELECT random()", "SELECT 1; SELECT 2",
    "WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r) SELECT x FROM r",
])
def test_unsafe_queries_are_rejected(query):
    report = evaluate_sql_case(fixture(), query)
    assert report["execution_status"] == "REJECTED"
    assert report["exact_result_match"] is False
    assert report["admission"] == "HOLD"


def test_read_only_cte_and_count_are_allowed():
    result = evaluate_sql_case(fixture(), "WITH t AS (SELECT id FROM incidents WHERE severity = 'high') SELECT COUNT(*) FROM t")
    assert result["exact_result_match"] is True


@pytest.mark.parametrize("change", [
    lambda f: f["tables"].append(f["tables"][0]),
    lambda f: f["tables"][0]["columns"].append({"name": "ID", "type": "INTEGER"}),
    lambda f: f.update({"extra": 1}),
    lambda f: f["tables"][0]["rows"].append([True, "high"]),
    lambda f: f["tables"][0]["rows"].append(["bad"]),
    lambda f: f.update({"expected_rows": [[True]]}),
])
def test_invalid_fixtures_rejected(change):
    f = fixture()
    change(f)
    with pytest.raises(ValueError):
        evaluate_sql_case(f, "SELECT 1")


def write(path, obj):
    raw = (json.dumps(obj, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def command(tmp_path):
    data = tmp_path / "case.json"
    prediction = tmp_path / "candidate.json"
    d = write(data, fixture())
    p = write(prediction, {"case_id": "cpu-1", "sql": "SELECT COUNT(*) FROM incidents WHERE severity='high'"})
    return [sys.executable, str(ROOT / "scripts" / "evaluate_sre_sql_holdout.py"),
            "--case", str(data), "--case-sha256", d,
            "--prediction", str(prediction), "--prediction-sha256", p], data, prediction


def test_cli_scores_pinned_bytes_only(tmp_path):
    argv, _, _ = command(tmp_path)
    p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, p.stderr
    result = json.loads(p.stdout)
    assert result["exact_result_match"] is True
    assert result["admission"] == "HOLD"


@pytest.mark.parametrize("fault", ["pin", "hardlink", "symlink", "case_mismatch", "duplicate_key"])
def test_cli_invalid_inputs_fail_without_report(tmp_path, fault):
    argv, data, prediction = command(tmp_path)
    if fault == "pin":
        argv[-1] = "0" * 64
    elif fault == "hardlink":
        prediction.unlink()
        os.link(data, prediction)
        argv[-1] = argv[argv.index("--case-sha256") + 1]
    elif fault == "symlink":
        prediction.unlink()
        prediction.symlink_to(data)
        argv[-1] = argv[argv.index("--case-sha256") + 1]
    elif fault == "case_mismatch":
        argv[-1] = write(prediction, {"case_id": "other", "sql": "SELECT 1"})
    else:
        raw = b'{"case_id":"cpu-1","case_id":"cpu-1","sql":"SELECT 1"}'
        prediction.write_bytes(raw)
        argv[-1] = hashlib.sha256(raw).hexdigest()
    p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert p.returncode == 3
    assert not p.stdout.strip()
    assert "HOLD" in p.stderr
