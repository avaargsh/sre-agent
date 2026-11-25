import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src' if (ROOT / 'src').exists() else ROOT
SCRIPT = ROOT / 'scripts' / 'verify_installed_endpoint.py'


@pytest.fixture
def cli(tmp_path):
    # Source-backed stand-in for the installed console entry point; this
    # exercises the actual CLI, not wheel installation itself.
    path = tmp_path / 'agentic-aiops'
    path.write_text(f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(SOURCE)!r})\nfrom agentic_aiops.cli import main\nmain()\n', encoding='utf-8')
    path.chmod(0o700)
    return path


def run_check(cli, tmp_path):
    return subprocess.run([sys.executable, str(SCRIPT), '--cli', str(cli)],
                          cwd=tmp_path, env=dict(os.environ, PYTHONPATH='/nonexistent'),
                          capture_output=True, text=True, timeout=60)


def test_smoke_accepts_actual_cli(cli, tmp_path):
    result = run_check(cli, tmp_path)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report == {'schema_version': 'endpoint-cli-smoke/v1', 'status': 'PASS',
                      'cases': ['scale-zero', 'readiness'], 'production_eligible': False}


@pytest.mark.parametrize('fault', ['exit', 'json', 'unsafe', 'invalid_accepted'])
def test_smoke_rejects_broken_cli(cli, tmp_path, fault):
    body = cli.read_text(encoding='utf-8')
    if fault == 'exit':
        body = f'#!{sys.executable}\nraise SystemExit(1)\n'
    elif fault == 'json':
        body = f'#!{sys.executable}\nprint("not JSON")\n'
    elif fault == 'unsafe':
        body = body.replace('from agentic_aiops.cli import main\nmain()',
                            'import json\nfrom agentic_aiops.demo_endpoint import render_demo\nreport=render_demo("readiness" if "readiness" in sys.argv else "scale-zero")\nreport["report"]["execution_authorized"]=True\nprint(json.dumps(report))')
    else:
        body = body.replace('main()\n', 'if "unknown" in sys.argv: raise SystemExit(0)\nmain()\n')
    cli.write_text(body, encoding='utf-8')
    result = run_check(cli, tmp_path)
    assert result.returncode != 0
    assert not result.stdout
    assert 'endpoint CLI smoke failed' in result.stderr
