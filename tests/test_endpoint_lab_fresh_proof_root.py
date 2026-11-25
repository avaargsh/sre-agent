"""Prevent stale or redirected lab proof paths before touching Kubernetes."""
from pathlib import Path
import shlex
import stat
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/run-kind.sh"


def preflight(root):
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("set -euo pipefail")
    stop = source.index("kubectl apply -f demo/k8s/golden-stack.yaml")
    fragment = source[start:stop]
    assert fragment.count("ROOT=/tmp/go-endpoint-proof") == 1
    return fragment.replace("ROOT=/tmp/go-endpoint-proof", f"ROOT={shlex.quote(str(root))}")


def run(root):
    return subprocess.run(["bash", "-c", preflight(root)], capture_output=True,
                          text=True, timeout=5)


def test_proof_root_starts_fresh_and_private(tmp_path):
    root = tmp_path / "proof"
    result = run(root)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in root.iterdir()) == ["control", "no-ready"]
    for path in (root, root / "control", root / "no-ready"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    marker = root / "control" / "archived.json"
    marker.write_bytes(b"original")
    second = run(root)
    assert second.returncode != 0, "existing run root must be rejected"
    assert marker.read_bytes() == b"original"


@pytest.mark.parametrize("kind", ["existing_dir", "symlink", "file"])
def test_existing_proof_path_rejected_without_mutation(tmp_path, kind):
    root = tmp_path / "proof"
    sentinel = tmp_path / "retained"
    sentinel.mkdir(mode=0o750)
    (sentinel / "prior.json").write_bytes(b"previous-run")
    original_mode = stat.S_IMODE(sentinel.stat().st_mode)
    if kind == "existing_dir":
        root.mkdir(mode=0o750)
        (root / "prior.json").write_bytes(b"previous-run")
    elif kind == "symlink":
        root.symlink_to(sentinel, target_is_directory=True)
    else:
        root.write_bytes(b"previous-run")
    result = run(root)
    assert result.returncode != 0
    assert not (root / "control").exists()
    assert not (root / "no-ready").exists()
    assert (sentinel / "prior.json").read_bytes() == b"previous-run"
    assert stat.S_IMODE(sentinel.stat().st_mode) == original_mode
    if kind == "symlink":
        assert root.is_symlink()
    elif kind == "file":
        assert root.read_bytes() == b"previous-run"
    else:
        assert (root / "prior.json").read_bytes() == b"previous-run"
