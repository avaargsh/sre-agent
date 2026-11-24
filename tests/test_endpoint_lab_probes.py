"""Exercise actual disposable-lab probe functions with a stubbed exec boundary."""
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/run-kind.sh"


@pytest.mark.parametrize("mode,expected,code", [
    ("healthy", 0, "200"),
    ("http_error", 0, "503"),
    ("refused", 0, "0"),
    ("timeout", 0, "0"),
    ("exec_error", 1, ""),
    ("dns_error", 1, ""),
    ("bad_status", 1, ""),
    ("missing_status", 1, ""),
])
@pytest.mark.parametrize("action", ["one", "phase"])
def test_probe_requires_completed_remote_command(tmp_path, mode, expected, code, action):
    source = SCRIPT.read_text(encoding="utf-8")
    functions = source[source.index("probe_one() {"):source.index("snapshot() {")]
    functions += source[source.index("probe() {"):source.index("judge() {")]
    harness = '''set -euo pipefail
kubectl() {
  # Emulate exec transport separately from the curl process on the remote Pod.
  if [[ "$MODE" == exec_error ]]; then printf '000'; return 1; fi
  local result status rc
  case "$MODE" in
    healthy) status=200; rc=0 ;;
    http_error) status=503; rc=0 ;;
    refused) status=000; rc=7 ;;
    timeout) status=000; rc=28 ;;
    dns_error) status=000; rc=6 ;;
    bad_status) status=999; rc=0 ;;
    missing_status) status=''; rc=0 ;;
  esac
  if [[ " $* " == *' sh -c '* ]]; then
    printf '%s:%s\\n' "$rc" "$status"
    return 0
  fi
  printf '%s' "$status"
  return "$rc"
}
sleep() { :; }
''' + functions + '\n'
    harness += 'probe_one\n' if action == "one" else 'probe "$OUT" during\n'
    result = subprocess.run(["bash", "-c", harness],
                            env=dict(os.environ, MODE=mode, OUT=str(tmp_path)),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == expected, result.stderr
    if action == "one":
        assert result.stdout.strip() == code
    else:
        assert (tmp_path / "during-probes.txt").read_text().splitlines() == ([code] * 3 if expected == 0 else [])
