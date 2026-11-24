"""Regression contract: test-admin must independently replay observer's exact API list snapshot."""
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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

def test_pin_opaque_resource_version_is_url_encoded(tmp_path):
    opaque = "rv/alpha?cursor=1&limit=0#fragment-β"
    observer = tmp_path / "opaque.json"
    observer.write_text(json.dumps(example(rv=opaque)), encoding="utf-8")

    result = call(tmp_path, observer)
    assert result.returncode == 0, result.stderr
    parsed = urlsplit(result.stdout.strip())
    query = parse_qs(parsed.query, strict_parsing=True)
    assert parsed.path == (
        "/apis/discovery.k8s.io/v1/namespaces/golden-demo/endpointslices"
    )
    assert parsed.fragment == ""
    assert query == {
        "labelSelector": ["kubernetes.io/service-name=checkout-api"],
        "limit": ["129"],
        "resourceVersion": [opaque],
        "resourceVersionMatch": ["Exact"],
    }


def test_reject_invalid_observer_versions_and_incomplete_lists(tmp_path):
    cases = [
        example(rv=""),
        example(rv="0"),
        example(rv="x" * 257),
        example(rv="β" * 129),  # 258 UTF-8 bytes despite only 129 code points.
        example(rv=123),
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
    opaque = "opaque/β?x=1&y=2"
    observer.write_text(json.dumps(example(rv=opaque)), encoding="utf-8")
    admin.write_text(json.dumps(example(rv=opaque)), encoding="utf-8")
    match = call(tmp_path, "--verify", observer, admin)
    assert match.returncode == 0, match.stderr
    drift = example()
    drift["items"][0]["endpoints"][0]["conditions"]["ready"] = False
    admin.write_text(json.dumps(drift), encoding="utf-8")
    mismatch = call(tmp_path, "--verify", observer, admin)
    assert mismatch.returncode != 0


def test_reject_unpaired_surrogate_in_unrelated_source_field(tmp_path):
    observer = tmp_path / "surrogate.json"
    observer.write_text(
        '{"kind":"EndpointSliceList","metadata":{"resourceVersion":"123",'
        '"annotations":{"note":"\\ud800"}},"items":[]}',
        encoding="utf-8",
    )
    result = call(tmp_path, observer)
    assert result.returncode == 3
    assert "UNKNOWN:" in result.stderr
    assert "Traceback" not in result.stderr


def test_reject_deeply_nested_source_json(tmp_path):
    observer = tmp_path / "deep.json"
    nested = "[" * 65 + "0" + "]" * 65
    observer.write_text(
        '{"kind":"EndpointSliceList","metadata":{"resourceVersion":"123",'
        '"annotation":' + nested + '},"items":[]}',
        encoding="utf-8",
    )
    result = call(tmp_path, observer)
    assert result.returncode == 3
    assert "UNKNOWN:" in result.stderr
    assert "Traceback" not in result.stderr
