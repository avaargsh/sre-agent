import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_sli_kind_evidence import QUERIES, verify_report


def fixture(status="HEALTHY", latency=0.2, traffic=2, age=1):
    limits = {"HEALTHY": (10, .001), "UNHEALTHY": (.001, .001), "UNKNOWN": (10, 1000000)}
    maximum, minimum = limits[status]
    report = {"status": status, "start": "2026-11-24T00:00:00Z", "end": "2026-11-24T00:00:20Z",
              "step_seconds": 5, "max_latency_seconds": maximum,
              "min_traffic_per_second": minimum, "max_sample_age_seconds": 10, "evidence": []}
    for query, value in zip(QUERIES, (latency, traffic, age)):
        raw = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": [
            {"metric": {}, "values": [[1795478400 + 5*i, str(value)] for i in range(5)]}]}}).encode()
        report["evidence"].append({"query": query, "response_sha256": hashlib.sha256(raw).hexdigest(),
                                   "raw_response_base64": base64.b64encode(raw).decode(), "series": 1, "samples": 5})
    return report


@pytest.mark.parametrize("status", ["HEALTHY", "UNHEALTHY", "UNKNOWN"])
def test_three_verdicts(status):
    verify_report(fixture(status), status)


@pytest.mark.parametrize("latency,traffic,age", [(11, 2, 1), (.2, 0, 1), (.2, 2, 11)])
def test_digest_valid_but_wrong_verdict(latency, traffic, age):
    with pytest.raises(ValueError):
        verify_report(fixture(latency=latency, traffic=traffic, age=age), "HEALTHY")


@pytest.mark.parametrize("field,value", [("query", "other"), ("samples", 6), ("series", 2), ("response_sha256", "0"*64)])
def test_evidence_metadata_mismatch(field, value):
    report = fixture()
    report["evidence"][0][field] = value
    with pytest.raises(ValueError):
        verify_report(report, "HEALTHY")


def test_policy_must_match_lab_policy():
    report = fixture()
    report["max_latency_seconds"] = 100
    with pytest.raises(ValueError):
        verify_report(report, "HEALTHY")


@pytest.mark.parametrize("mutation", ["timestamp", "missing", "warning", "partial", "duplicate"])
def test_rehashed_invalid_source(mutation):
    report = fixture()
    entry = report["evidence"][0]
    source = json.loads(base64.b64decode(entry["raw_response_base64"]))
    series = source["data"]["result"][0]
    if mutation == "timestamp":
        series["values"][0][0] += 1
    elif mutation == "missing":
        series["values"].pop()
    elif mutation == "warning":
        source["warnings"] = ["incomplete"]
    elif mutation == "partial":
        source["isPartial"] = True
    else:
        source["data"]["result"].append(series)
    raw = json.dumps(source).encode()
    entry["raw_response_base64"] = base64.b64encode(raw).decode()
    entry["response_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        verify_report(report, "HEALTHY")
