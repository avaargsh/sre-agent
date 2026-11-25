"""LAB exact-resourceVersion pinning must reject incomplete LIST metadata."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "demo/go-endpoint/pin_during.py"


@pytest.mark.parametrize(
    "extra, accepted",
    [
        ("", True),
        (',"continue":"","remainingItemCount":0', True),
        (',"continue":"next"', False),
        (',"continue":null', False),
        (',"remainingItemCount":1', False),
        (',"remainingItemCount":-1', False),
        (',"remainingItemCount":null', False),
        (',"remainingItemCount":"0"', False),
        (',"remainingItemCount":0.0', False),
        (',"remainingItemCount":false', False),
        (',"remainingItemCount":{}', False),
    ],
)
def test_pin_complete_list_only(tmp_path, extra, accepted):
    source = tmp_path / "list.json"
    source.write_text(
        '{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"'
        + extra + '},"items":[]}', encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(source)], capture_output=True, text=True,
        timeout=5,
    )
    if accepted:
        assert result.returncode == 0, result.stderr
        assert "resourceVersion=25&resourceVersionMatch=Exact" in result.stdout
    else:
        assert result.returncode == 3
        assert result.stdout == ""
        assert "UNKNOWN" in result.stderr


@pytest.mark.parametrize("invalid_side", ["observer", "admin", "both", "neither"])
def test_verify_rejects_invalid_list_on_either_side(tmp_path, invalid_side):
    paths = {name: tmp_path / f"{name}.json" for name in ("observer", "admin")}
    for name, path in paths.items():
        count = 1 if invalid_side in (name, "both") else 0
        path.write_text(
            '{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25",'
            '"remainingItemCount":' + str(count) + '},"items":[]}', encoding="utf-8"
        )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--verify", str(paths["observer"]), str(paths["admin"])],
        capture_output=True, text=True, timeout=5,
    )
    if invalid_side == "neither":
        assert result.returncode == 0, result.stderr
        assert "PASS" in result.stdout
    else:
        assert result.returncode == 3
        assert "UNKNOWN" in result.stderr
        assert result.stdout == ""


@pytest.mark.parametrize("mutation", ["grow", "shrink", "same_size"])
def test_pin_reader_rejects_file_mutated_after_initial_stat(tmp_path, monkeypatch, mutation):
    spec = importlib.util.spec_from_file_location("endpoint_pin", SCRIPT)
    pin = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(pin)

    target = tmp_path / "observer.json"
    original = (
        b'{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},'
        b'"items":[]}'
    )
    target.write_bytes(original)
    real_fstat = os.fstat
    calls = 0

    def mutate_after_first_stat(fd):
        nonlocal calls
        info = real_fstat(fd)
        calls += 1
        if calls == 1:
            if mutation == "grow":
                target.write_bytes(original + b" ")
            elif mutation == "shrink":
                target.write_bytes(original[:-1])
            else:
                target.write_bytes(b"X" * len(original))
                os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return info

    monkeypatch.setattr(pin.os, "fstat", mutate_after_first_stat)
    with pytest.raises(ValueError, match="changed during read"):
        pin.read_bounded_regular_file(target)
    assert calls >= 2
