"""Regular-file admission for the offline Endpoint CLI input boundary."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agentic_aiops.endpoint_input import read_bounded_input


pytestmark = pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"),
    reason="requires safe POSIX file-open flags",
)


def test_preserves_exact_bytes_and_inclusive_limit(tmp_path):
    path = tmp_path / "evidence.json"
    raw = b'{"value": 1}\n'
    path.write_bytes(raw)
    assert read_bounded_input(path, len(raw)) == raw


@pytest.mark.parametrize("kind", ["empty", "oversized", "directory", "missing", "symlink", "dangling_symlink", "fifo"])
def test_rejects_invalid_file_without_blocking(tmp_path, kind):
    path = tmp_path / "evidence.json"
    if kind == "empty":
        path.touch()
    elif kind == "oversized":
        path.write_bytes(b"12345")
    elif kind == "directory":
        path.mkdir()
    elif kind in ("symlink", "dangling_symlink"):
        target = tmp_path / "target.json"
        if kind == "symlink":
            target.write_bytes(b"{}")
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path)
    # Run in a subprocess so a FIFO regression fails with a timeout, not a hung suite.
    result = subprocess.run(
        [sys.executable, "-c", "import sys; from agentic_aiops.endpoint_input import read_bounded_input\n"
         "try: read_bounded_input(sys.argv[1], 4)\n"
         "except (ValueError, OSError): sys.exit(3)", str(path)],
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src")),
        capture_output=True, timeout=3,
    )
    assert result.returncode == 3, result.stderr
    assert not result.stdout


def test_rejects_invalid_bound(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_bytes(b"{}")
    with pytest.raises(ValueError):
        read_bounded_input(path, 0)


def test_rejects_growth_after_initial_size_check(tmp_path, monkeypatch):
    from types import SimpleNamespace

    path = tmp_path / "evidence.json"
    path.write_bytes(b"12345")
    real_fstat = os.fstat

    def stale_size(fd):
        info = real_fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_size=1)

    monkeypatch.setattr(os, "fstat", stale_size)
    with pytest.raises(ValueError):
        read_bounded_input(path, 4)
