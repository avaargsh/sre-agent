"""Regression: do not label transient cluster startup as a healthy G2i baseline."""
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

CHECK = pathlib.Path(__file__).resolve().parents[1] / "demo" / "go-networkpolicy" / "check_healthy.py"

def sample():
    return {
        "schema_version": "sre.dns-probe/v1",
        "service_ip": "10.96.2.3",
        "host": "checkout-api.golden-demo.svc.cluster.local",
        "dns_ok": True,
        "dns_addresses": ["10.96.2.3"],
        "dns_error": "",
        "name_http_status": 200,
        "name_http_error": "",
        "direct_http_status": 200,
        "direct_http_attempts": [200, 200, 200],
        "direct_http_errors": ["", "", ""],
    }

def run_check(tmp_path, body, ip="10.96.2.3"):
    path = tmp_path / "probe.log"
    path.write_text(json.dumps(body), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(CHECK), str(path), ip],
        capture_output=True, text=True, check=False,
    )

def test_fully_healthy_baseline_passes(tmp_path):
    result = run_check(tmp_path, sample())
    assert result.returncode == 0
    assert "PASS" in result.stdout

@pytest.mark.parametrize("mutation", [
    lambda x: x.update(name_http_status=0),
    lambda x: x.update(direct_http_status=0),
    lambda x: x.update(direct_http_attempts=[0, 200, 200]),
    lambda x: x.update(direct_http_attempts=[200, 0, 200]),
    lambda x: x.update(direct_http_errors=["timeout", "", ""]),
    lambda x: x.update(dns_ok=False),
    lambda x: x.update(dns_error="refused"),
    lambda x: x.update(dns_addresses=["10.96.2.4"]),
    lambda x: x.update(schema_version="some-forged-output"),
])
def test_unstable_or_inconsistent_baseline_fails(tmp_path, mutation):
    body = sample()
    mutation(body)
    assert run_check(tmp_path, body).returncode == 3

def test_missing_field_malformed_or_wrong_clusterip_fails(tmp_path):
    body = sample()
    del body["direct_http_attempts"]
    assert run_check(tmp_path, body).returncode == 3
    assert run_check(tmp_path, sample(), "10.96.2.5").returncode == 3
    log = tmp_path / "malformed.log"
    log.write_text('{"dns_ok": true,', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(CHECK), str(log), "10.96.2.3"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 3
