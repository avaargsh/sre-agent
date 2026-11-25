import json

import pytest

from agentic_aiops.cli import main
from agentic_aiops.evaluation import evaluate_aiops
from agentic_aiops.scenario import ScenarioOutcomeError, load_evaluation_scenario


def payload():
    return {
        "case_id": "case-1",
        "bundle": {"incident": {"incident_id": "inc-1", "summary": "demo", "severity": "sev2"}},
        "outcome": {
            "automation_eligible": False,
            "executed_without_approval": False,
            "expected_path": "human_review",
            "selected_path": "human_review",
            "recovery_required": False,
        },
    }


@pytest.mark.parametrize("field", ["tool_calls", "required_tools"])
@pytest.mark.parametrize("value", ["metrics", {"metrics": True}, None, 1, [1], ["metrics", {}]])
def test_tool_fields_require_json_string_arrays(tmp_path, field, value):
    data = payload()
    data["outcome"][field] = value
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ScenarioOutcomeError, match=field):
        load_evaluation_scenario(path)


def test_valid_tool_arrays_preserve_order_and_repeated_calls(tmp_path):
    data = payload()
    data["outcome"]["tool_calls"] = ["metrics", "metrics", "logs"]
    data["outcome"]["required_tools"] = ["metrics"]
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    scenario = load_evaluation_scenario(path)
    assert scenario.outcome.tool_calls == ("metrics", "metrics", "logs")
    result = evaluate_aiops([scenario.bundle], [scenario.outcome])
    assert result.unnecessary_tool_rate == pytest.approx(1 / 3)


def test_omitted_tool_fields_default_to_empty(tmp_path):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(payload()), encoding="utf-8")
    scenario = load_evaluation_scenario(path)
    assert scenario.outcome.tool_calls == scenario.outcome.required_tools == ()


def test_cli_rejects_malformed_tool_list_without_partial_metrics(tmp_path, monkeypatch, capsys):
    data = payload()
    valid = tmp_path / "valid.json"
    valid.write_text(json.dumps(data), encoding="utf-8")
    data["outcome"]["required_tools"] = "metrics"
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["agentic-aiops", "evaluate-scenarios", str(valid), str(invalid), "--metrics-only"])
    with pytest.raises(SystemExit) as exc:
        main()
    output = capsys.readouterr()
    assert exc.value.code == 2
    assert not output.out
    assert "outcome.required_tools" in output.err
    assert "Traceback" not in output.err
