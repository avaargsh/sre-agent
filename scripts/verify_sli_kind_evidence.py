"""Recompute the three lab SLI verdicts from stored Prometheus samples.

This checks content consistency only, not source or runner authenticity.
"""
import base64
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

QUERIES = ("max(checkout_request_latency_seconds)",
           "sum(rate(checkout_requests_total[20s]))",
           "max(time() - timestamp(checkout_request_latency_seconds))")
POLICIES = {"HEALTHY": (10, .001), "UNHEALTHY": (.001, .001), "UNKNOWN": (10, 1000000)}
DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def canonical_fields(obj, fields):
    """Reject aliases of consumed schema fields, not case-sensitive map keys."""
    require(type(obj) is dict, "invalid source object")
    names = {field.casefold(): field for field in fields}
    for key in obj:
        canonical = names.get(key.casefold())
        require(canonical is None or key == canonical, "noncanonical source field")


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def verify_report(report, expected):
    maximum, minimum = POLICIES[expected]
    for key, value in (("max_latency_seconds", maximum), ("min_traffic_per_second", minimum),
                       ("max_sample_age_seconds", 10), ("step_seconds", 5)):
        require(number(report[key]) and report[key] == value, "lab policy mismatch")
    start, end = (datetime.fromisoformat(report[k].replace("Z", "+00:00")) for k in ("start", "end"))
    require(start.tzinfo is not None and end.tzinfo is not None, "missing timezone")
    start, end = start.timestamp(), end.timestamp()
    require(0 < start < end <= 9000000000 and end-start == 20 and start % 5 == 0, "invalid lab window")
    evidence = report["evidence"]
    require(type(evidence) is list and len(evidence) == 3, "missing evidence")
    values = []
    for entry, query in zip(evidence, QUERIES):
        require(entry["query"] == query, "unexpected query")
        raw = base64.b64decode(entry["raw_response_base64"], validate=True)
        require(len(raw) <= 2 << 20 and hashlib.sha256(raw).hexdigest() == entry["response_sha256"], "source digest or size mismatch")
        source = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        canonical_fields(source, ("status", "data", "warnings", "isPartial", "partialResponse"))
        canonical_fields(source["data"], ("resultType", "result"))
        require(source["status"] == "success" and source["data"]["resultType"] == "matrix", "invalid matrix")
        require(source.get("warnings", []) == [] and source.get("isPartial", False) is False
                and source.get("partialResponse", False) is False, "incomplete source")
        rows = source["data"]["result"]
        require(type(rows) is list and 1 <= len(rows) <= 16, "invalid series count")
        seen, samples = set(), []
        for row in rows:
            canonical_fields(row, ("metric", "values"))
            metric = row["metric"]
            require(type(metric) is dict and all(k and type(v) is str for k, v in metric.items()), "invalid labels")
            labels = tuple(sorted(metric.items()))
            require(labels not in seen, "duplicate series")
            seen.add(labels)
            points = row["values"]
            require(type(points) is list and len(points) == 5, "incomplete sample window")
            for i, point in enumerate(points):
                require(type(point) is list and len(point) == 2, "invalid sample")
                stamp, value = point
                require(number(stamp) and 0 < stamp <= 9000000000 and abs(stamp-(start+5*i)) <= .001, "sample timestamp mismatch")
                require(type(value) is str and DECIMAL.fullmatch(value), "invalid decimal")
                value = float(value)
                require(math.isfinite(value) and value >= 0, "invalid sample value")
                samples.append(value)
        require(type(entry["series"]) is int and entry["series"] == len(rows) and
                type(entry["samples"]) is int and entry["samples"] == len(samples), "count mismatch")
        values.append(samples)
    latency, traffic, age = values
    require(max(age) <= 10, "lab requires fresh samples")
    verdict = "UNKNOWN" if min(traffic) < minimum else "UNHEALTHY" if max(latency) > maximum else "HEALTHY"
    require(verdict == expected and report["status"] == verdict, "recomputed verdict mismatch")


def main():
    for expected in POLICIES:
        path = Path(f"/tmp/go-sli-{expected.lower()}.json")
        with path.open("rb") as stream:
            raw = stream.read((10 << 20) + 1)
        require(len(raw) <= 10 << 20, "oversized lab report")
        verify_report(json.loads(raw.decode("utf-8"), object_pairs_hook=unique), expected)
        print("recomputed_lab_verdict", expected)


if __name__ == "__main__":
    main()
