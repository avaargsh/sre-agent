"""Reject invalid Unicode at the signed Episode dataset admission boundary.

An escaped lone UTF-16 surrogate is legal JSON syntax but not a Unicode
scalar. It must not enter Qwen3 prompts or abort an entire GRPO batch.
"""
import json

import pytest

from agentic_aiops.grpo_training import build_prompt, load_episodes_bytes


def episode():
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": "unicode-training-001",
        "fault_family": "pod-restarts",
        "split": "train",
        "alert": "Pod restarts after a limit change",
        "observations": [
            {
                "evidence_id": "pod-events",
                "tool": "kubernetes.get_events",
                "text": "Last termination OOMKilled",
            },
        ],
        "oracle": {
            "answerable": True,
            "root_cause_id": "oom_killed",
            "required_evidence_ids": ["pod-events"],
        },
    }


@pytest.mark.parametrize("target", ["alert", "observation"])
@pytest.mark.parametrize("surrogate", [0xD800, 0xDFFF])
def test_reject_unpaired_utf16_surrogate_in_oracle_free_prompt_sources(target, surrogate):
    obj = episode()
    if target == "alert":
        obj["alert"] = "restarts " + chr(surrogate)
    else:
        obj["observations"][0]["text"] = "events " + chr(surrogate)
    # JSONL bytes are valid UTF-8. The invalid character only materializes
    # after JSON decoding: raw.decode("utf-8") is not a sufficient guard.
    raw = (json.dumps(obj, ensure_ascii=True) + "\n").encode("utf-8")
    with pytest.raises(ValueError, match="Unicode|UTF-8|surrogate"):
        load_episodes_bytes(raw)


def test_accept_well_formed_escaped_surrogate_pair_as_valid_scalar():
    obj = episode()
    obj["observations"][0]["text"] = "GPU alert \U0001f6f0"
    raw = (json.dumps(obj, ensure_ascii=True) + "\n").encode("utf-8")
    got, = load_episodes_bytes(raw)
    assert "\U0001f6f0" in build_prompt(got)
    assert build_prompt(got).encode("utf-8")
