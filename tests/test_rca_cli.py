import json

import pytest

from agentic_aiops.cli import main


def bundle_payload():
    return {
        "incident": {"incident_id": "inc-1", "summary": "checkout latency", "severity": "sev2", "scope": "checkout"},
        "evidence": [{"evidence_id": "e-1", "source": "prometheus", "observation": "pool saturated"}],
        "hypotheses": [
            {"hypothesis_id": "h-1", "statement": "pool saturation", "evidence_ids": ["e-1"], "status": "supported"},
            {"hypothesis_id": "h-2", "statement": "network failure", "status": "unverified"},
        ],
    }


@pytest.mark.parametrize("scenario", [False, True])
def test_render_rca_from_bundle_or_scenario(tmp_path, monkeypatch, capsys, scenario):
    payload = bundle_payload()
    if scenario:
        payload = {"case_id": "case-1", "bundle": payload}
    path = tmp_path / "input.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    argv = ["agentic-aiops", "render-rca", str(path)]
    if scenario:
        argv.append("--scenario")
    monkeypatch.setattr("sys.argv", argv)
    main()
    output = capsys.readouterr()
    assert not output.err
    assert "# Incident inc-1" in output.out
    assert "**SUPPORTED** pool saturation — evidence: e-1" in output.out
    assert "**UNVERIFIED** network failure — evidence: none" in output.out
    assert "not independent verification" in output.out
    assert path.read_bytes() == before


@pytest.mark.parametrize("data, scenario, message", [
    (None, False, "cannot read RCA input"),
    (b"{", False, "expected UTF-8 JSON"),
    (b"\xff", False, "expected UTF-8 JSON"),
    (b"{}", False, "invalid evidence bundle"),
    (b"[]", False, "invalid evidence bundle"),
    (b"{}", True, "invalid evidence bundle"),
])
def test_render_rca_rejects_invalid_input_without_report(tmp_path, monkeypatch, capsys, data, scenario, message):
    path = tmp_path / "bad.json"
    if data is not None:
        path.write_bytes(data)
    argv = ["agentic-aiops", "render-rca", str(path)]
    if scenario:
        argv.append("--scenario")
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exc:
        main()
    output = capsys.readouterr()
    assert exc.value.code == 2
    assert not output.out
    assert message in output.err
    assert "Traceback" not in output.err
