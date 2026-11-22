#!/usr/bin/env python3
"""Summarize a SMALL, labelled disposable-kind Oracle suite.

This is not a statistical benchmark, model accuracy number or signed truth.
The test-admin episodes are withheld from the read-only baseline until scoring.
"""
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path("/tmp/go-oracle-proof")
SCENARIOS = {
    "control": ("NO_FAULT", "UNKNOWN", "CORRECT_REJECTION"),
    "misroute": ("SERVICE_TARGETPORT_MISROUTED", "SERVICE_TARGETPORT_MISROUTED", "MATCHED_INJECTED_FAULT"),
    "selector": ("SERVICE_SELECTOR_MISMATCH", "SERVICE_SELECTOR_MISMATCH", "MATCHED_INJECTED_FAULT"),
}


def checked_source(source):
    raw = base64.b64decode(source["raw_response_base64"], validate=True)
    if hashlib.sha256(raw).hexdigest() != source["response_sha256"]:
        raise AssertionError("Original source digest mismatch")
    return json.loads(raw)


def read_triplet(name):
    directory = ROOT / name
    episode = json.loads((directory / "episode.json").read_text())
    prediction = json.loads((directory / "prediction.json").read_text())
    result = json.loads((directory / "evaluation.json").read_text())
    for phase in ("before", "during", "after"):
        checked_source(episode[phase])
    checked_source(prediction["observed"])
    if result["episode_id"] != episode["episode_id"]:
        raise AssertionError("Independent Oracle episode differs from evaluated result")
    if prediction["classification"] != result["prediction"]:
        raise AssertionError("Prediction disagrees with frozen evaluation")
    if result["production_causality_verified"] is not False:
        raise AssertionError("Disallowed production causal claim")
    return episode, prediction, result


def main():
    confusion = {}
    true_fault = 0
    true_control = 0
    hits = 0
    false_positives = 0
    fault_abstentions = 0
    wrong_fault_class = 0
    correct_rejections = 0
    items = []
    seen_ids = set()
    for name, (truth, label, verdict) in SCENARIOS.items():
        episode, prediction, score = read_triplet(name)
        if episode["episode_id"] in seen_ids:
            raise AssertionError("Duplicate episode IDs")
        seen_ids.add(episode["episode_id"])
        if episode["scenario"] != truth:
            raise AssertionError(f"Wrong admin-labelled truth in {name}")
        if prediction["classification"] != label or score["verdict"] != verdict:
            raise AssertionError(f"Regression in {name}: {prediction}, {score}")
        confusion.setdefault(truth, {})[prediction["classification"]] = 1
        if truth == "NO_FAULT":
            true_control += 1
            if prediction["classification"] == "UNKNOWN":
                correct_rejections += 1
            else:
                false_positives += 1
        else:
            true_fault += 1
            if prediction["classification"] == truth:
                hits += 1
            elif prediction["classification"] == "UNKNOWN":
                fault_abstentions += 1
            else:
                wrong_fault_class += 1
        items.append({
            "episode_id": episode["episode_id"],
            "test_admin_truth": truth,
            "read_only_prediction": prediction["classification"],
            "verdict": score["verdict"],
        })
    summary = {
        "schema_version": "sre.oracle-suite/v1",
        "scope": "three disposable-kind labelled episodes; deterministic Service rules only",
        "episodes": len(items),
        "fault_episodes": true_fault,
        "normal_controls": true_control,
        "correct_fault_classes": hits,
        "correct_normal_rejections": correct_rejections,
        "false_positive_controls": false_positives,
        "fault_abstentions": fault_abstentions,
        "wrong_fault_classes": wrong_fault_class,
        "confusion_counts": confusion,
        "items": items,
        "population_metrics_supported": False,
        "production_causality_verified": False,
    }
    (ROOT / "suite-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("PASS: bounded 3-episode confusion-count summary:", summary["episodes"], "episodes")


if __name__ == "__main__":
    main()
