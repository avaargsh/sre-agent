"""Non-finite numbers from exponent overflow must not escape JSON admission."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from test_endpoint_capture_count import capture_fixture, UID

SCRIPT = Path(__file__).resolve().parents[1] / 'demo/go-endpoint/verify_capture.py'


@pytest.mark.parametrize('field', ['service', 'endpoint_slices', 'capture_report'])
def test_exponent_overflow_rejected_without_publishing(tmp_path, field):
    capture = capture_fixture()
    if field == 'capture_report':
        # Keep 1e9999 as a JSON exponent, not Python's Infinity literal.
        raw = json.dumps(capture, separators=(',', ':')).replace(
            '"ready_endpoints":0', '"ready_endpoints":0,"extra_nonfinite":1e9999')
    else:
        for i, name in enumerate(('service_before', 'endpoint_slices', 'service_after')):
            if (field == 'service' and name == 'endpoint_slices') or (field == 'endpoint_slices' and name != 'endpoint_slices'):
                continue
            original = base64.b64decode(capture[name + '_raw'])
            assert original.endswith(b'}')
            injected = original[:-1] + b',"overflow":1e9999}'
            capture[name + '_raw'] = base64.b64encode(injected).decode('ascii')
            digest = hashlib.sha256(injected).hexdigest()
            capture['report'][name + '_sha256'] = digest
            capture['report']['read_timeline'][i]['response_sha256'] = digest
        raw = json.dumps(capture, separators=(',', ':'))
    source = tmp_path / 'capture.json'
    source.write_text(raw, encoding='utf-8')
    destination = tmp_path / 'output'
    destination.mkdir(mode=0o700)
    result = subprocess.run([sys.executable, '-O', str(SCRIPT), str(source), str(destination), UID],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 3, (result.returncode, result.stdout, result.stderr, field)
    assert not result.stdout
    assert result.stderr.startswith('UNKNOWN:')
    assert list(destination.iterdir()) == []
