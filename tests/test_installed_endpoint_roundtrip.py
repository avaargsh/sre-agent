"""Check the installed-smoke driver's roundtrip gate using a synthetic CLI double."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_installed_endpoint.py"


@pytest.mark.parametrize("fault", ["none", "export_missing", "replay_missing", "wrong_digest", "wrong_report", "invalid_accepted"])
def test_smoke_requires_export_and_replay(tmp_path, fault):
    cli = tmp_path / "cli"
    cli.write_text(f"#!{sys.executable}\n" + '''import hashlib, json, os, pathlib, sys
fault = os.environ["SMOKE_FAULT"]
args = sys.argv[1:]
def report(case):
    scale = case == "scale-zero"
    return {"schema_version": "endpoint-offline-demo/v1", "synthetic": True, "case": case,
            "report": {"schema_version": "rca-report/v1", "independently_verified": False,
                       "execution_authorized": False,
                       "endpoint_observation": {"reported_classification": "NO_READY_ENDPOINTS_OBSERVED",
                                                "reported_ready_endpoints": 0, "source_authenticated": False},
                       "topology_context": {"replica_assessment": {"observations": [{"association": "template_candidate" if scale else "owner_chain", "status": "zero_desired_and_available" if scale else "availability_shortfall"}]},
                                            "readiness_assessment": {"observations": [] if scale else [{"status": "reported_not_ready"}]}},
                       "hypotheses": [{"supplied_status": "unverified"}] * 3,
                       "investigation_plan": {"collection_authorized": False, "execution_authorized": False,
                                              "checks": [{"status": "pending_evidence"}] * 3}}}
if args[0] == "demo-endpoint":
    case = args[args.index("--case") + 1] if "--case" in args else "scale-zero"
    if case not in ("scale-zero", "readiness"):
        sys.exit(2)
    if "--format" in args:
        if fault == "export_missing": sys.exit(2)
        print(json.dumps({"schema_version": "endpoint-offline-fixture/v1", "synthetic": True, "case": case, "capture": {}, "topology": {}}))
    else:
        print(json.dumps(report(case)))
elif args[0] == "render-endpoint-fixture":
    if fault == "replay_missing": sys.exit(2)
    raw = pathlib.Path(args[1]).read_bytes()
    fixture = json.loads(raw)
    if fixture.get("synthetic") is not True:
        sys.exit(0 if fault == "invalid_accepted" else 2)
    value = report(fixture["case"])
    value["fixture_sha256"] = "0" * 64 if fault == "wrong_digest" else hashlib.sha256(raw).hexdigest()
    if fault == "wrong_report": value["report"]["execution_authorized"] = True
    print(json.dumps(value))
else:
    sys.exit(2)
''', encoding="utf-8")
    cli.chmod(0o700)
    result = subprocess.run([sys.executable, str(SCRIPT), "--cli", str(cli)],
                            env=dict(os.environ, SMOKE_FAULT=fault),
                            capture_output=True, text=True, timeout=30)
    if fault == "none":
        assert result.returncode == 0, result.stderr
        assert '"status": "PASS"' in result.stdout
    else:
        assert result.returncode == 1, result.stdout + result.stderr
        assert not result.stdout
