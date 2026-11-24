"""Exercise the LAB shell preflight without contacting a Kubernetes cluster."""
import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/run-kind.sh"


@pytest.mark.parametrize(
    "mode, action, expected_rc, expected_stdout",
    [
        ("dedup", "count", 0, "1"),
        ("zero", "count", 0, "0"),
        ("unknown", "count", 3, ""),
        ("invalid_count", "count", 1, ""),
        ("wrong_class", "count", 3, ""),
        ("bad_json", "count", 1, ""),
        ("transition", "wait", 0, "EndpointSlice Ready endpoints: 0 (zero)"),
        ("failure", "wait", 1, ""),
        ("unknown", "wait", 1, ""),
    ],
)
def test_preflight_uses_go_verdict(tmp_path, mode, action, expected_rc, expected_stdout):
    source = SCRIPT.read_text(encoding="utf-8")
    functions = source[source.index("ready_count() {"):source.index("# EndpointSlice convergence alone")]
    fixture = tmp_path / "slices.json"
    item = {
        "metadata": {"namespace": "golden-demo", "labels": {"kubernetes.io/service-name": "checkout-api"}},
        "endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": True}}],
    }
    fixture.write_text(json.dumps({"kind": "EndpointSliceList", "metadata": {"resourceVersion": "25"}, "items": [item, item]}))
    binary = tmp_path / "sre-agent"
    binary.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
assert sys.argv[1:] == ["diagnose-endpoints", "--observed-service", os.environ["SERVICE_FILE"], "--observed-endpointslices", os.environ["SLICE_FILE"], "--expected-target-port", "8080", "--expected-selector", "app=checkout-api", "--out", "-"]
assert pathlib.Path(os.environ["SERVICE_FILE"]).is_file()
mode = os.environ["MODE"]
if mode == "transition":
    marker = pathlib.Path(os.environ["MARKER"])
    if not marker.exists():
        marker.touch()
        sys.exit(3)
    mode = "zero"
if mode == "unknown": sys.exit(3)
if mode == "failure": sys.exit(1)
if mode == "bad_json": print("not json"); sys.exit(0)
count = {"dedup": 1, "zero": 0, "invalid_count": True, "wrong_class": 1}[mode]
classification = "UNKNOWN" if mode == "wrong_class" else ("READY_ENDPOINTS_OBSERVED" if count else "NO_READY_ENDPOINTS_OBSERVED")
print(json.dumps({"schema_version": "sre.endpoint-observation/v1", "ready_endpoints": count, "classification": classification}))
''', encoding="utf-8")
    binary.chmod(0o700)
    env = dict(os.environ, SRE_AGENT_BIN=str(binary), SLICE_FILE=str(fixture),
               SERVICE_FILE=str(fixture)+".service.json", MODE=mode, MARKER=str(tmp_path / "marker"))
    harness = '''set -euo pipefail
service() { printf '{}\\n' > "$2"; }
slices() { :; }
sleep() { :; }
seq() { printf '1\\n2\\n'; }
''' + functions + '\n'
    harness += 'ready_count "$SLICE_FILE"\n' if action == "count" else 'wait_ready zero "$SLICE_FILE"\n'
    result = subprocess.run(["bash", "-c", harness], env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == expected_rc, result.stderr
    assert result.stdout.strip() == expected_stdout
    if mode == "transition":
        assert (tmp_path / "marker").exists()
    if action == "wait" and mode == "failure":
        assert "never converged" not in result.stderr
