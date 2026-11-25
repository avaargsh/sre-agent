from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .bundle import EvidenceBundle
from .evaluation import AutomationOutcome


@dataclass(frozen=True)
class EvaluationScenario:
    case_id: str
    bundle: EvidenceBundle
    outcome: AutomationOutcome


class ScenarioOutcomeError(ValueError):
    """An outcome field is missing or has the wrong JSON type."""


def _tool_names(outcome_data: dict, field: str) -> tuple[str, ...]:
    values = outcome_data.get(field, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ScenarioOutcomeError(f"outcome.{field} must be a JSON array of strings")
    return tuple(values)


def load_evaluation_scenario(
    path: str | Path,
) -> EvaluationScenario:
    payload = json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )

    case_id = str(payload["case_id"])
    outcome_data = dict(payload["outcome"])
    for field in ("automation_eligible", "executed_without_approval", "recovery_required"):
        if not isinstance(outcome_data.get(field), bool):
            raise ScenarioOutcomeError(f"outcome.{field} must be a JSON boolean")
    recovered = outcome_data.get("recovered")
    if recovered is not None and not isinstance(recovered, bool):
        raise ScenarioOutcomeError("outcome.recovered must be a JSON boolean or null")

    return EvaluationScenario(
        case_id=case_id,
        bundle=EvidenceBundle.from_dict(
            payload["bundle"]
        ),
        outcome=AutomationOutcome(
            case_id=case_id,
            automation_eligible=outcome_data["automation_eligible"],
            executed_without_approval=outcome_data["executed_without_approval"],
            expected_path=str(
                outcome_data["expected_path"]
            ),
            selected_path=str(
                outcome_data["selected_path"]
            ),
            recovery_required=outcome_data["recovery_required"],
            recovered=recovered,
            tool_calls=_tool_names(outcome_data, "tool_calls"),
            required_tools=_tool_names(outcome_data, "required_tools"),
        ),
    )
