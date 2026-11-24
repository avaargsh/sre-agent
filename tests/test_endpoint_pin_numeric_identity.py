"""The LAB exact-RV comparison must preserve JSON scalar types and number tokens."""
import subprocess
import sys
from pathlib import Path

import pytest

PIN = Path(__file__).resolve().parents[1] / "demo/go-endpoint/pin_during.py"


def source(value):
    return ('{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25"},'
            '"items":[],"extra":' + value + '}').encode("utf-8")


def call(*args):
    return subprocess.run([sys.executable, str(PIN), *map(str, args)],
                          capture_output=True, text=True, timeout=5)


@pytest.mark.parametrize("observer,admin,accepted", [
    ("1", "1", True),
    ('{"a":1,"b":false}', '{ "b":false, "a":1 }', True),
    ("1", "true", False),
    ("0", "false", False),
    ("1", "1.0", False),
    ("1e0", "1.0", False),
    ("0", "-0", False),
    ("0.123456789012345678901", "0.123456789012345678902", False),
    ('"1"', "1", False),
    ('[1,2]', '[2,1]', False),
])
def test_exact_rv_preserves_numeric_identity(tmp_path, observer, admin, accepted):
    a, b = tmp_path / "observer.json", tmp_path / "admin.json"
    a.write_bytes(source(observer))
    b.write_bytes(source(admin))
    result = call("--verify", a, b)
    if accepted:
        assert result.returncode == 0, result.stderr
        assert "PASS" in result.stdout
    else:
        assert result.returncode == 3
        assert result.stdout == ""
        assert "UNKNOWN" in result.stderr


@pytest.mark.parametrize("raw", [
    source("NaN"), source("Infinity"), source("-Infinity"),
    source("1").decode("utf-8").encode("utf-16"),
    b'{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25",'
    b'"remainingItemCount":-0},"items":[]}',
])
def test_pin_rejects_noncanonical_source(tmp_path, raw):
    path = tmp_path / "source.json"
    path.write_bytes(raw)
    result = call(path)
    assert result.returncode == 3
    assert result.stdout == ""
    assert "UNKNOWN" in result.stderr
