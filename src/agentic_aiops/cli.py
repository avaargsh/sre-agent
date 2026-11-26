from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .bundle import EvidenceBundle
from .endpoint_report import attach_topology_context, render_endpoint_rca, summarize_endpoint_capture
from .evaluation import evaluate_aiops
from .release_metrics import evaluation_metric_map
from .report import render_rca_json, render_rca_markdown
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
        help="scenario JSON files with distinct case IDs",
    )
    evaluate.add_argument(
        "--metrics-only",
        action="store_true",
    )

    rca = subparsers.add_parser(
        "render-rca", help="render a local Python evidence bundle as Markdown or JSON"
    )
    rca.add_argument("path")
    rca.add_argument("--format", choices=("markdown", "json"), default="markdown")
    rca.add_argument("--scenario", action="store_true", help="read the bundle field of a scenario")

    endpoint = subparsers.add_parser(
        "render-endpoint-capture", help="display an archived Go Endpoint observation"
    )
    endpoint.add_argument("path")
    endpoint.add_argument("--format", choices=("summary", "rca-json"), default="summary")

    endpoint.add_argument("--topology-snapshot", help="attach a separate local Service inventory to RCA JSON")

    demo = subparsers.add_parser("demo-endpoint", help="run a synthetic offline Endpoint RCA example")
    demo.add_argument("--case", choices=("scale-zero", "readiness"), default="scale-zero")

    demo.add_argument("--format", choices=("report", "fixture"), default="report")

    fixture = subparsers.add_parser("render-endpoint-fixture", help="render an exported synthetic Endpoint fixture")
    fixture.add_argument("path")

    args = parser.parse_args()

    if args.command == "render-endpoint-fixture":
        from .demo_endpoint import render_exported_fixture

        try:
            result = render_exported_fixture(args.path)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            fixture.error("invalid synthetic Endpoint fixture")
        print(json.dumps(result, indent=2, allow_nan=False))
        return

    if args.command == "demo-endpoint":
        from .demo_endpoint import export_demo_fixture, render_demo

        try:
            result = export_demo_fixture(args.case) if args.format == "fixture" else render_demo(args.case)
        except (OSError, ValueError):
            demo.error("cannot render offline demo")
        print(json.dumps(result, indent=2, allow_nan=False))
        return

    if args.command == "render-endpoint-capture":
        if args.topology_snapshot is not None and args.format != "rca-json":
            endpoint.error("--topology-snapshot requires --format rca-json")
        try:
            summary = summarize_endpoint_capture(args.path)
            if args.format == "rca-json":
                summary = render_endpoint_rca(summary)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            endpoint.error(f"{args.path!r}: invalid endpoint capture")
        if args.topology_snapshot is not None:
            try:
                summary = attach_topology_context(summary, args.topology_snapshot)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
                endpoint.error("invalid or mismatched topology snapshot")
        print(json.dumps(summary, indent=2, allow_nan=False))
        return

    if args.command == "render-rca":
        try:
            payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
            if args.scenario:
                payload = payload["bundle"]
            if args.format == "json":
                report = render_rca_json(payload)
            else:
                bundle = EvidenceBundle.from_dict(payload)
                report = render_rca_markdown(bundle)
        except OSError:
            rca.error(f"{args.path!r}: cannot read RCA input")
        except (UnicodeDecodeError, json.JSONDecodeError):
            rca.error(f"{args.path!r}: expected UTF-8 JSON")
        except (KeyError, TypeError, ValueError, AttributeError):
            rca.error(f"{args.path!r}: invalid evidence bundle")
        if args.format == "json":
            print(report)
            return
        print(
            "> Offline rendering of supplied evidence and hypothesis statuses; "
            "not independent verification or execution authorization.\n\n"
            + report,
            end="",
        )
        return

    scenarios = []
    case_ids: set[str] = set()
    for path in args.scenarios:
        try:
            scenario = load_evaluation_scenario(path)
        except OSError:
            evaluate.error(f"{path!r}: cannot read scenario file")
        except (UnicodeDecodeError, json.JSONDecodeError):
            evaluate.error(f"{path!r}: expected UTF-8 JSON")
        except ScenarioOutcomeError as exc:
            evaluate.error(f"{path!r}: {exc}")
        except (KeyError, TypeError, ValueError, AttributeError):
            evaluate.error(f"{path!r}: invalid scenario structure")
        if scenario.case_id in case_ids:
            evaluate.error(f"{path!r}: duplicate scenario case ID")
        case_ids.add(scenario.case_id)
        scenarios.append(scenario)
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
