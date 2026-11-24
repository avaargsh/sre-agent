"""Check the disposable lab's zero-Pod convergence gate without a cluster."""
import json
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/run-kind.sh"
POD_LIST = {"apiVersion": "v1", "kind": "PodList",
            "metadata": {"resourceVersion": "123"}, "items": []}


@pytest.mark.parametrize("payload,expected", [
    (POD_LIST, 0),
    ({**POD_LIST, "items": [{}]}, 1),
    ({key: value for key, value in POD_LIST.items() if key != "items"}, 1),
    ({**POD_LIST, "items": {}}, 1),
    ({**POD_LIST, "items": None}, 1),
    ({**POD_LIST, "kind": "List"}, 1),
    ({**POD_LIST, "apiVersion": "v2"}, 1),
    ({**POD_LIST, "metadata": {}}, 1),
    ({**POD_LIST, "metadata": {"resourceVersion": "0"}}, 1),
    ({**POD_LIST, "metadata": {"resourceVersion": "123", "continue": "next"}}, 1),
    ({**POD_LIST, "metadata": {"resourceVersion": "123", "remainingItemCount": 1}}, 1),
    ({**POD_LIST, "metadata": {"resourceVersion": "123", "remainingItemCount": False}}, 1),
    ({**POD_LIST, "metadata": {"resourceVersion": "123", "remainingItemCount": 0, "continue": ""}}, 0),
])
def test_zero_pods_requires_complete_native_list(tmp_path, payload, expected):
    source = SCRIPT.read_text(encoding="utf-8")
    function = source[source.index("wait_zero_pods() {"):source.index("# Keep *all* warm-up probes")]
    fixture = tmp_path / "source.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")
    env = dict(os.environ, SOURCE=str(fixture), OUTPUT=str(tmp_path / "zero.json"))
    harness = '''set -euo pipefail
kubectl() { cat "$SOURCE"; }
seq() { printf '1\\n'; }
sleep() { :; }
''' + function + '\nwait_zero_pods "$OUTPUT"\n'
    result = subprocess.run(["bash", "-c", harness], env=env,
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == expected, result.stdout + result.stderr
