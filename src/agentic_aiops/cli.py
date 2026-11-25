from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .evaluation import evaluate_aiops
from .release_metrics import evaluation_metric_map
from .scenario import ScenarioOutcomeError, load_evaluation_scenario


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentic-aiops"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    evaluate = subparsers.add_parser(
        "evaluate-scenarios"
    )
    evaluate.add_argument(
        "scenarios",
        nargs="+",
    )
    evaluate.add_argument(
        "--metrics-only",
        action="store_true",
    )

    args = parser.parse_args()

    scenarios = []
    for path in args.scenarios:
        try:
            scenarios.append(load_evaluation_scenario(path))
        except OSError:
            evaluate.error(f"{path!r}: cannot read scenario file")
        except (UnicodeDecodeError, json.JSONDecodeError):
            evaluate.error(f"{path!r}: expected UTF-8 JSON")
        except ScenarioOutcomeError as exc:
            evaluate.error(f"{path!r}: {exc}")
    result = evaluate_aiops(
        [
            item.bundle
            for item in scenarios
        ],
        [
            item.outcome
            for item in scenarios
        ],
    )

    payload = (
        evaluation_metric_map(result)
        if args.metrics_only
        else {
            "evaluation": asdict(result),
            "metrics": evaluation_metric_map(
                result
            ),
        }
    )

    print(
        json.dumps(
            payload,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
