import json

import pytest

from agentic_aiops.cli import main


def payload():
    return {
        "incident": {"incident_id": "inc-1", "summary": "latency", "severity": "sev2"},
        "evidence": [
            {"evidence_id": "e-1", "source": "metrics", "observation": "high latency"},
            {"evidence_id": "e-2", "source": "logs", "observation": "first"},
            {"evidence_id": "e-2", "source": "logs", "observation": "second"},
        ],
        "hypotheses": [
            {"hypothesis_id": "h-1", "statement": "linked", "status": "supported", "evidence_ids": ["e-1"]},
            {"hypothesis_id": "h-2", "statement": "incomplete", "status": "supported", "evidence_ids": ["e-3", "e-2"]},
            {"hypothesis_id": "h-3", "statement": "no links", "status": "unverified"},
        ],
        "metadata": {"execution_authorized": True},
    }


@pytest.mark.parametrize("scenario", [False, True])
def test_json_report_distinguishes_supplied_status_and_reference_checks(tmp_path, monkeypatch, capsys, scenario):
    data = payload()
    path = tmp_path / "input.json"
    path.write_text(json.dumps({"bundle": data} if scenario else data), encoding="utf-8")
    argv = ["agentic-aiops", "render-rca", str(path), "--format", "json"]
    if scenario:
        argv.append("--scenario")
    monkeypatch.setattr("sys.argv", argv)
    main()
    out = capsys.readouterr()
    report = json.loads(out.out)
    assert not out.err
    assert report["schema_version"] == "rca-report/v1"
    assert report["independently_verified"] is False
    assert report["execution_authorized"] is False
    assert report["incident"]["incident_id"] == "inc-1"
    assert len(report["evidence"]) == 3
    assert report["duplicate_evidence_ids"] == ["e-2"]
    linked, incomplete, empty = report["hypotheses"]
    assert linked["supplied_status"] == "supported"
    assert linked["references_resolved"] is True
    assert incomplete["supplied_status"] == "supported"
    assert incomplete["references_resolved"] is False
    assert incomplete["missing_evidence_ids"] == ["e-3"]
    assert incomplete["ambiguous_evidence_ids"] == ["e-2"]
    assert empty["references_resolved"] is False


@pytest.mark.parametrize("bad", ["e-1", {"e-1": True}, [1], [""]])
def test_json_report_rejects_malformed_reference_arrays(tmp_path, monkeypatch, capsys, bad):
    data = payload()
    data["hypotheses"][0]["evidence_ids"] = bad
    path = tmp_path / "input.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "render-rca", str(path), "--format", "json"])
    with pytest.raises(SystemExit) as exc:
        main()
    out = capsys.readouterr()
    assert exc.value.code == 2
    assert not out.out
    assert "invalid evidence bundle" in out.err
