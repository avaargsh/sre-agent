"""Regression contract: test-admin must independently replay observer's exact API list snapshot."""
import json
import subprocess
import sys
from pathlib import Path

PIN = Path(__file__).resolve().parents[1] / "demo" / "go-endpoint" / "pin_during.py"

def example(rv="123", ready=True):
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSliceList",
        "metadata": {"resourceVersion": rv},
        "items": [{
            "metadata": {"uid": "es-1", "name": "checkout-1",
                         "namespace": "golden-demo",
                         "labels": {"kubernetes.io/service-name": "checkout-api"}},
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.244.0.10"],
                "conditions": {"ready": ready}
            }]
        }]
    }

def call(tmp_path, *args):
    return subprocess.run([sys.executable, str(PIN), *[str(a) for a in args]],
                          text=True, capture_output=True, timeout=10)

def test_pin_exact_observer_resource_version(tmp_path):
    observer = tmp_path / "observer.json"
    observer.write_text(json.dumps(example()), encoding="utf-8")
    result = call(tmp_path, observer)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "/apis/discovery.k8s.io/v1/namespaces/golden-demo/endpointslices"
        "?labelSelector=kubernetes.io%2Fservice-name%3Dcheckout-api"
        "&limit=129&resourceVersion=123&resourceVersionMatch=Exact"
    )

def test_reject_unsafe_observer_versions_and_incomplete_lists(tmp_path):
    cases = [
        example(rv=""),
        example(rv="123&limit=0"),
        example(rv="-1"),
        {**example(), "metadata": {"resourceVersion": "123", "continue": "next"}},
        {**example(), "kind": "List"},
    ]
    for i, doc in enumerate(cases):
        path = tmp_path / f"bad-{i}.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        result = call(tmp_path, path)
        assert result.returncode != 0, (i, result.stdout)

def test_reject_duplicate_metadata_fields_before_pinning(tmp_path):
    observer = tmp_path / "duplicate.json"
    observer.write_text(
        '{"kind":"EndpointSliceList","metadata":{"resourceVersion":"123",'
        '"resourceVersion":"124"},"items":[]}', encoding="utf-8")
    result = call(tmp_path, observer)
    assert result.returncode != 0

def test_verify_admin_re_read_exact_snapshot(tmp_path):
    observer = tmp_path / "observer.json"
    admin = tmp_path / "admin.json"
    observer.write_text(json.dumps(example()), encoding="utf-8")
    admin.write_text(json.dumps(example()), encoding="utf-8")
    match = call(tmp_path, "--verify", observer, admin)
    assert match.returncode == 0, match.stderr
    drift = example()
    drift["items"][0]["endpoints"][0]["conditions"]["ready"] = False
    admin.write_text(json.dumps(drift), encoding="utf-8")
    mismatch = call(tmp_path, "--verify", observer, admin)
    assert mismatch.returncode != 0
