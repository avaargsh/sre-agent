import json

import pytest

from agentic_aiops.cli import main
from agentic_aiops.evaluation import evaluate_aiops
from agentic_aiops.scenario import load_evaluation_scenario


def scenario_payload():
    return {
        "case_id": "case-1",
        "bundle": {"incident": {"incident_id": "inc-1", "summary": "demo", "severity": "sev2"}},
        "outcome": {
            "automation_eligible": False,
            "executed_without_approval": True,
            "expected_path": "human_review",
            "selected_path": "human_review",
            "recovery_required": True,
            "recovered": False,
        },
    }


@pytest.mark.parametrize("field", ["automation_eligible", "executed_without_approval", "recovery_required", "recovered"])
@pytest.mark.parametrize("value", ["false", 0, [], {}])
def test_non_boolean_outcome_flags_are_rejected(tmp_path, field, value):
    payload = scenario_payload()
    payload["outcome"][field] = value
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=field):
        load_evaluation_scenario(path)


@pytest.mark.parametrize("value", [False, True, None])
def test_valid_recovery_flags_preserve_metrics(tmp_path, value):
    payload = scenario_payload()
    payload["outcome"]["recovered"] = value
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    scenario = load_evaluation_scenario(path)
    assert scenario.outcome.recovered is value
    result = evaluate_aiops([scenario.bundle], [scenario.outcome])
    assert result.false_automation_rate == 1.0
    assert result.recovery_success_rate == float(value is True)


def test_cli_rejects_invalid_boolean_without_partial_metrics(tmp_path, monkeypatch, capsys):
    payload = scenario_payload()
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(payload), encoding="utf-8")
    payload["outcome"]["automation_eligible"] = "false"
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "evaluate-scenarios", str(valid), str(invalid), "--metrics-only"])
    with pytest.raises(SystemExit) as exc:
        main()
    output = capsys.readouterr()
    assert exc.value.code == 2
    assert not output.out
    assert "automation_eligible" in output.err
    assert "Traceback" not in output.err
