import json
from pathlib import Path

import pytest

from agentic_aiops.cli import main


ROOT = Path(__file__).resolve().parents[1]


def test_cli_outputs_gate_metric_map(
    monkeypatch,
    capsys,
) -> None:
    scenario = (
        ROOT
        / "benchmarks/scenarios/checkout-latency.json"
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "agentic-aiops",
            "evaluate-scenarios",
            str(scenario),
            "--metrics-only",
        ],
    )

    main()
    payload = json.loads(
        capsys.readouterr().out
    )

    assert payload[
        "false_automation_rate"
    ] == 0.0
    assert payload[
        "unsupported_claim_rate"
    ] == 0.0
    assert payload[
        "escalation_accuracy"
    ] == 1.0
    assert payload[
        "recovery_success_rate"
    ] == 1.0


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "cannot read scenario file"),
        (b"invalid JSON", "expected UTF-8 JSON"),
        (b'{"private_dummy_marker": 1}', "invalid scenario structure"),
        (b"[]", "invalid scenario structure"),
        (b"\xff", "expected UTF-8 JSON"),
    ],
)
def test_cli_rejects_unreadable_or_malformed_input_without_partial_metrics(
    tmp_path, monkeypatch, capsys, content, message
) -> None:
    valid = ROOT / "benchmarks/scenarios/checkout-latency.json"
    invalid = tmp_path / "bad-scenario.json"
    if content is not None:
        invalid.write_bytes(content)
    monkeypatch.setattr(
        "sys.argv",
        ["agentic-aiops", "evaluate-scenarios", str(valid), str(invalid), "--metrics-only"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    output = capsys.readouterr()
    assert exc.value.code == 2
    assert not output.out
    assert f"{str(invalid)!r}: {message}" in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("distinct_id", [False, True])
def test_cli_evaluation_batch_requires_distinct_case_ids(
    tmp_path, monkeypatch, capsys, distinct_id
) -> None:
    fixture = ROOT / "benchmarks/scenarios/checkout-latency.json"
    second = tmp_path / "second.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    if distinct_id:
        data["case_id"] += "-second"
    second.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["agentic-aiops", "evaluate-scenarios", str(fixture), str(second)]
    )

    if distinct_id:
        main()
        output = capsys.readouterr()
        assert json.loads(output.out)["evaluation"]["automation_cases"] == 2
        assert not output.err
    else:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
        output = capsys.readouterr()
        assert not output.out
        assert f"{str(second)!r}: duplicate scenario case ID" in output.err


@pytest.mark.parametrize("invalid_case_id", [False, 12, None, "", " ", " checkout "])
def test_cli_rejects_case_ids_that_would_be_normalized(
    tmp_path, monkeypatch, capsys, invalid_case_id
) -> None:
    fixture = ROOT / "benchmarks/scenarios/checkout-latency.json"
    invalid = tmp_path / "invalid-case.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    data["case_id"] = invalid_case_id
    invalid.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["agentic-aiops", "evaluate-scenarios", str(fixture), str(invalid)]
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert f"{str(invalid)!r}: case_id must be a nonempty JSON string" in output.err
