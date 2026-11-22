"""GRPO SRE offline contract: independent Oracle, no model-owned reward inputs."""

import json

import pytest

from agentic_aiops.grpo_training import (
    build_prompt,
    load_episodes,
    make_trl_reward,
    score_completion,
)


def episode(*, episode_id="episode-1", family="pod-oom", split="train",
            answerable=True):
    return {
        "schema_version": "sre.grpo.episode/v1",
        "episode_id": episode_id,
        "fault_family": family,
        "split": split,
        "alert": "Pod restarts are rising",
        "observations": [
            {"evidence_id": "e1", "tool": "kubernetes.get_pods",
             "text": "Last termination reason OOMKilled"},
            {"evidence_id": "e2", "tool": "kubernetes.get_events",
             "text": "Container killed after memory limit reached"},
        ],
        "oracle": {
            "answerable": answerable,
            "root_cause_id": "oom_killed" if answerable else "unknown",
            "required_evidence_ids": ["e1", "e2"] if answerable else [],
        },
    }


def write_jsonl(tmp_path, rows):
    path = tmp_path / "episodes.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8")
    return path


def answer(root="oom_killed", evidence=("e1", "e2"), stop="verified", **extra):
    return json.dumps({
        "root_cause_id": root,
        "evidence_ids": list(evidence),
        "stop_reason": stop,
        **extra,
    })


def test_correct_answer_rewards_only_independently_cited_evidence(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    assert score_completion(ep, answer()) == pytest.approx(1.0)
    assert score_completion(ep, answer(evidence=("e1",))) < 0
    assert score_completion(ep, answer(evidence=("e1", "made-up"))) == -1.0
    assert score_completion(ep, answer(root="dns_failure")) == -1.0
    assert score_completion(ep, answer(stop="insufficient_evidence")) < 0


def test_invented_tool_calls_and_actions_are_never_rewarded(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    assert score_completion(ep, answer(tool_calls=0)) == -1.0
    assert score_completion(ep, answer(action="kubectl delete pod")) == -1.0
    assert score_completion(ep, answer(evidence=("e1", "e1", "e2"))) == -1.0
    assert score_completion(ep, '{"root_cause_id":"oom_killed","root_cause_id":"other",'
                                '"evidence_ids":["e1","e2"],"stop_reason":"verified"}') == -1.0


def test_correct_abstention_when_oracle_unanswerable(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode(answerable=False)]))
    assert score_completion(ep, answer(root="unknown", evidence=(),
                                        stop="insufficient_evidence")) == 1.0
    assert score_completion(ep, answer()) == -1.0
    assert score_completion(ep, answer(root="unknown", evidence=(),
                                        stop="verified")) < 0


def test_prompt_never_exposes_oracle_or_split(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    prompt = build_prompt(ep)
    assert "OOMKilled" in prompt
    assert "oom_killed" not in prompt
    assert "required_evidence_ids" not in prompt
    assert "train" not in prompt
    assert "e1" in prompt


def test_rejects_duplicate_keys_unknown_fields_and_unsafe_tools(tmp_path):
    raw = ('{"schema_version":"sre.grpo.episode/v1","episode_id":"a",'
           '"episode_id":"b"}\n')
    file = tmp_path / "dup.jsonl"
    file.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_episodes(file)
    bad = episode()
    bad["observations"][0]["tool"] = "kubernetes.delete_pod"
    with pytest.raises(ValueError, match="read-only"):
        load_episodes(write_jsonl(tmp_path, [bad]))
    bad = episode()
    bad["unsafe"] = True
    with pytest.raises(ValueError, match="fields"):
        load_episodes(write_jsonl(tmp_path, [bad]))


def test_split_leakage_and_duplicate_ids_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="fault_family"):
        load_episodes(write_jsonl(tmp_path, [
            episode(), episode(episode_id="e2", split="test")]))
    with pytest.raises(ValueError, match="episode_id"):
        load_episodes(write_jsonl(tmp_path, [
            episode(), episode(family="node-oom")]))


def test_oracle_must_reference_real_observations(tmp_path):
    bad = episode()
    bad["oracle"]["required_evidence_ids"] = ["missing"]
    with pytest.raises(ValueError, match="required_evidence_ids"):
        load_episodes(write_jsonl(tmp_path, [bad]))
    bad = episode(answerable=False)
    bad["oracle"]["root_cause_id"] = "oom_killed"
    with pytest.raises(ValueError, match="unknown"):
        load_episodes(write_jsonl(tmp_path, [bad]))


def test_reward_adapter_requires_trusted_episode_identity(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    reward = make_trl_reward([ep])
    assert reward([answer()], episode_id=["episode-1"]) == [1.0]
    with pytest.raises(ValueError, match="episode_id"):
        reward([answer()], episode_id=["other"])
    with pytest.raises(ValueError, match="episode_id"):
        reward([answer()])
    with pytest.raises(ValueError, match="length"):
        reward([answer(), answer()], episode_id=["episode-1"])


def test_rejects_oversized_candidate_and_prose_wrappers(tmp_path):
    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    assert score_completion(ep, "here is my answer: " + answer()) == -1.0
    assert score_completion(ep, "x" * 20000) == -1.0
    assert score_completion(ep, '{"root_cause_id":"oom_killed","evidence_ids":[],'
                                '"stop_reason":"verified","other":null}') == -1.0


def test_qwen3_template_disables_thinking_and_detects_truncation(tmp_path):
    from agentic_aiops.grpo_training import qwen3_chat_rows

    class ToyTokenizer:
        def apply_chat_template(self, messages, **kwargs):
            assert kwargs["enable_thinking"] is False
            assert kwargs["add_generation_prompt"] is True
            return "[assistant] " + messages[0]["content"]

        def __call__(self, text, **kwargs):
            return {"input_ids": text.split()}

    ep, = load_episodes(write_jsonl(tmp_path, [episode()]))
    rows = qwen3_chat_rows(ToyTokenizer(), [ep])
    assert rows[0]["episode_id"] == "episode-1"
    assert "oom_killed" not in rows[0]["prompt"]
    with pytest.raises(ValueError, match="truncated"):
        qwen3_chat_rows(ToyTokenizer(), [ep], max_prompt_tokens=1)
    with pytest.raises(ValueError, match="completion budget"):
        qwen3_chat_rows(ToyTokenizer(), [ep], max_completion_tokens=1)


def test_cross_split_exact_evidence_leakage_fails_even_if_family_renamed(tmp_path):
    left = episode(episode_id="train-1", family="pod-memory", split="train")
    right = episode(episode_id="test-1", family="renamed-memory", split="test")
    with pytest.raises(ValueError, match="content leakage"):
        load_episodes(write_jsonl(tmp_path, [left, right]))

    # Evidence IDs and benign whitespace do not make a repeated case independent.
    right["observations"][0]["evidence_id"] = "new-evidence-id"
    right["observations"][0]["text"] = "Last   termination reason  OOMKilled"
    right["oracle"]["required_evidence_ids"] = ["new-evidence-id", "e2"]
    with pytest.raises(ValueError, match="content leakage"):
        load_episodes(write_jsonl(tmp_path, [left, right]))


def test_same_content_within_same_split_is_allowed_for_lab_repeats(tmp_path):
    left = episode(episode_id="train-1", family="pod-memory", split="train")
    right = episode(episode_id="train-2", family="pod-memory", split="train")
    loaded = load_episodes(write_jsonl(tmp_path, [left, right]))
    assert len(loaded) == 2
