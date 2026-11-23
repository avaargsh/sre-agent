"""Bound untrusted JSON nesting before model reward or dataset admission.

A 20 KiB nested array is under the JSONL line budget but can make Python's
json.loads raise RecursionError. No malformed input may terminate the GRPO
reward batch or produce an uncaught exception during episode admission.
"""

import json

import pytest

from agentic_aiops.grpo_training import (
    _strict_json,
    load_episodes_bytes,
    score_completion,
    SREEpisode,
    Observation,
    Oracle,
)


def test_strict_json_rejects_deep_arrays_without_parser_recursion():
    with pytest.raises(ValueError, match="nesting|invalid JSON"):
        _strict_json("[" * 12_000 + "0" + "]" * 12_000)


@pytest.mark.parametrize(
    "opening,closing",
    [("[", "]"), ('{"value":', "}")],
)
def test_strict_json_limits_containers_to_64_levels(opening, closing):
    assert _strict_json(opening * 64 + "0" + closing * 64) is not None
    with pytest.raises(ValueError, match="nesting"):
        _strict_json(opening * 65 + "0" + closing * 65)


def test_json_brackets_inside_escaped_strings_are_not_structure():
    text = "[" * 200 + "}" * 200 + '\\"' + "[" * 200
    assert _strict_json(json.dumps({"text": text})) == {"text": text}
    with pytest.raises(ValueError, match="duplicate"):
        _strict_json('{"key":0,"key":1}')


def test_deep_dataset_record_fails_as_validation_error():
    # This remains below the 32 KiB per-line cap.
    raw = ("[" * 12_000 + "0" + "]" * 12_000 + "\n").encode()
    with pytest.raises(ValueError, match="nesting|invalid JSON"):
        load_episodes_bytes(raw)


def test_model_completion_with_deep_json_is_penalized_not_executed():
    episode = SREEpisode(
        episode_id="ep-1", fault_family="pod-memory", split="train",
        alert="Pod OOM",
        observations=(Observation("e1", "kubernetes.get_pods", "OOMKilled"),),
        oracle=Oracle(True, "oom_killed", ("e1",)),
    )
    completion = "[" * 65 + "0" + "]" * 65
    assert score_completion(episode, completion) == -1.0
