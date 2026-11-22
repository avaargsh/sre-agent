"""Offline SRE GRPO training contract (no Kubernetes writes or model imports).

The Oracle is held by the reward process. Prompts contain only frozen,
read-only observations. A model cannot report its own tool cost or authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


SCHEMA = "sre.grpo.episode/v1"
READ_ONLY_TOOLS = frozenset({
    "kubernetes.get_pods",
    "kubernetes.get_events",
    "kubernetes.get_logs",
    "kubernetes.get_nodes",
    "prometheus.query",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_SPLITS = frozenset({"train", "validation", "test"})
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_LINE_BYTES = 32 * 1024
_MAX_COMPLETION_BYTES = 8192


@dataclass(frozen=True)
class Observation:
    evidence_id: str
    tool: str
    text: str


@dataclass(frozen=True)
class Oracle:
    answerable: bool
    root_cause_id: str
    required_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class SREEpisode:
    episode_id: str
    fault_family: str
    split: str
    alert: str
    observations: tuple[Observation, ...]
    oracle: Oracle


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _strict_json(data: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_object_pairs,
                          parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("invalid JSON") from exc


def _fields(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{name} fields must be exactly {sorted(expected)}")
    return value


def _id(value: Any, name: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _text(value: Any, name: str, max_chars: int) -> str:
    if type(value) is not str or not value.strip() or len(value) > max_chars:
        raise ValueError(f"invalid {name}")
    return value


def _ids(value: Any, name: str, max_count: int = 32) -> tuple[str, ...]:
    if type(value) is not list or len(value) > max_count:
        raise ValueError(f"invalid {name}")
    result = tuple(_id(item, name) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"duplicate {name}")
    return result


def _decode_episode(data: Any) -> SREEpisode:
    raw = _fields(data, {
        "schema_version", "episode_id", "fault_family", "split",
        "alert", "observations", "oracle",
    }, "episode")
    if raw["schema_version"] != SCHEMA:
        raise ValueError("unsupported schema_version")
    episode_id = _id(raw["episode_id"], "episode_id")
    family = _id(raw["fault_family"], "fault_family")
    split = raw["split"]
    if type(split) is not str or split not in _SPLITS:
        raise ValueError("invalid split")
    alert = _text(raw["alert"], "alert", 1024)
    observations = raw["observations"]
    if type(observations) is not list or not 1 <= len(observations) <= 32:
        raise ValueError("observations must contain 1-32 read-only records")
    result: list[Observation] = []
    for item in observations:
        obs = _fields(item, {"evidence_id", "tool", "text"}, "observation")
        tool = obs["tool"]
        if type(tool) is not str or tool not in READ_ONLY_TOOLS:
            raise ValueError("non-read-only or unsupported observation tool")
        result.append(Observation(
            evidence_id=_id(obs["evidence_id"], "evidence_id"),
            tool=tool,
            text=_text(obs["text"], "observation text", 4096),
        ))
    known = {obs.evidence_id for obs in result}
    if len(known) != len(result):
        raise ValueError("duplicate evidence_id")

    truth = _fields(raw["oracle"], {
        "answerable", "root_cause_id", "required_evidence_ids",
    }, "oracle")
    if type(truth["answerable"]) is not bool:
        raise ValueError("oracle answerable must be boolean")
    root = _id(truth["root_cause_id"], "root_cause_id")
    required = _ids(truth["required_evidence_ids"], "required_evidence_ids")
    if not set(required).issubset(known):
        raise ValueError("required_evidence_ids must refer to observations")
    if truth["answerable"]:
        if root == "unknown" or not required:
            raise ValueError("answerable Oracle needs a root cause and evidence")
    elif root != "unknown" or required:
        raise ValueError("unanswerable Oracle must use unknown and no required evidence")
    return SREEpisode(
        episode_id=episode_id, fault_family=family, split=split,
        alert=alert, observations=tuple(result),
        oracle=Oracle(
            answerable=truth["answerable"], root_cause_id=root,
            required_evidence_ids=required,
        ),
    )


def load_episodes(path: str | Path) -> tuple[SREEpisode, ...]:
    """Read bounded JSONL and reject cross-split fault-family leakage."""
    raw = Path(path).read_bytes()
    if not raw or len(raw) > _MAX_FILE_BYTES:
        raise ValueError("empty or oversized episode dataset")
    try:
        data = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 episode dataset") from exc
    episodes: list[SREEpisode] = []
    ids: set[str] = set()
    family_splits: dict[str, str] = {}
    content_splits: dict[tuple[str, tuple[tuple[str, str], ...]], str] = {}
    for line in data.splitlines():
        if not line.strip():
            raise ValueError("blank JSONL record")
        if len(line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise ValueError("oversized JSONL record")
        ep = _decode_episode(_strict_json(line))
        if ep.episode_id in ids:
            raise ValueError(f"duplicate episode_id: {ep.episode_id}")
        ids.add(ep.episode_id)
        former = family_splits.setdefault(ep.fault_family, ep.split)
        if former != ep.split:
            raise ValueError(f"fault_family split leakage: {ep.fault_family}")
        # Prevent a renamed family or changed evidence IDs from moving the
        # same frozen observation text between train and independent holdouts.
        # This is exact normalized-content checking, not semantic near-duplicate
        # detection or an externally authenticated source-provenance check.
        normalize = lambda value: " ".join(value.casefold().split())
        fingerprint = (
            normalize(ep.alert),
            tuple(sorted(
                (obs.tool, normalize(obs.text))
                for obs in ep.observations
            )),
        )
        previous_split = content_splits.setdefault(fingerprint, ep.split)
        if previous_split != ep.split:
            raise ValueError(f"cross-split content leakage: {ep.episode_id}")
        episodes.append(ep)
    if not episodes:
        raise ValueError("no episodes")
    return tuple(episodes)


def build_prompt(episode: SREEpisode) -> str:
    """Never serialize the oracle, split or a write-capable tool instruction."""
    entries = "\n".join(
        f"- [{item.evidence_id}] {item.tool}: {item.text}"
        for item in episode.observations
    )
    return (
        "You are a read-only Kubernetes SRE diagnostic observer. "
        "Use only the evidence IDs below. Do not request or perform writes. "
        "Reply with a single JSON object with exactly root_cause_id, "
        "evidence_ids and stop_reason. stop_reason is verified or "
        "insufficient_evidence. If evidence is insufficient, return "
        "root_cause_id=unknown and no evidence_ids.\n"
        f"Alert: {episode.alert}\nEvidence:\n{entries}"
    )


def training_rows(episodes: Sequence[SREEpisode]) -> list[dict[str, str]]:
    """TRL sees a prompt and opaque ID, never Oracle truth columns."""
    return [
        {"prompt": build_prompt(ep), "episode_id": ep.episode_id}
        for ep in episodes if ep.split == "train"
    ]


def score_completion(episode: SREEpisode, completion: Any) -> float:
    """Hard-fail invalid, unsafe, hallucinated or unsupported conclusions.

    Intentionally no model-provided tool-call count/latency or self-scored Judge.
    Those require separately authenticated environment receipts.
    """
    if type(completion) is not str:
        return -1.0
    if len(completion.encode("utf-8")) > _MAX_COMPLETION_BYTES:
        return -1.0
    try:
        raw = _fields(_strict_json(completion), {
            "root_cause_id", "evidence_ids", "stop_reason",
        }, "completion")
        root = _id(raw["root_cause_id"], "root_cause_id")
        cited = _ids(raw["evidence_ids"], "evidence_ids")
        stop = raw["stop_reason"]
        if type(stop) is not str or stop not in {
            "verified", "insufficient_evidence",
        }:
            return -1.0
    except (ValueError, TypeError, UnicodeEncodeError):
        return -1.0

    known = {obs.evidence_id for obs in episode.observations}
    if not set(cited).issubset(known):
        return -1.0
    oracle = episode.oracle
    if not oracle.answerable:
        if root == "unknown" and not cited and stop == "insufficient_evidence":
            return 1.0
        return -1.0
    if root != oracle.root_cause_id:
        return -1.0
    if not set(oracle.required_evidence_ids).issubset(cited):
        return -0.5
    if stop != "verified":
        return -0.5
    extras = len(set(cited) - set(oracle.required_evidence_ids))
    return max(0.0, 1.0 - 0.05 * extras)


def make_trl_reward(
    episodes: Sequence[SREEpisode],
) -> Callable[..., list[float]]:
    """Reward adapter using trusted episode ID from the dataset column."""
    index = {ep.episode_id: ep for ep in episodes}
    if len(index) != len(episodes):
        raise ValueError("duplicate episode_id in reward lookup")

    def reward(
        completions: list[str],
        episode_id: list[str] | None = None,
        **_kwargs: Any,
    ) -> list[float]:
        if episode_id is None:
            raise ValueError("missing trusted episode_id")
        if len(completions) != len(episode_id):
            raise ValueError("completions and episode_id length mismatch")
        if any(type(key) is not str or key not in index for key in episode_id):
            raise ValueError("unknown trusted episode_id")
        return [
            score_completion(index[key], candidate)
            for key, candidate in zip(episode_id, completions)
        ]

    return reward


def qwen3_chat_rows(
    tokenizer: Any,
    episodes: Sequence[SREEpisode],
    *,
    max_prompt_tokens: int = 1024,
    max_completion_tokens: int = 192,
) -> list[dict[str, str]]:
    """Render explicit non-thinking chat template; refuse truncated evidence.

    Gold labels are used *only* to check whether a valid answer can fit
    the completion budget; they are never attached to a model input row.
    """
    result: list[dict[str, str]] = []
    for ep in episodes:
        if ep.split != "train":
            continue
        prompt = tokenizer.apply_chat_template(
            [{"role": "user", "content": build_prompt(ep)}],
            tokenize=False, add_generation_prompt=True, enable_thinking=False,
        )
        if type(prompt) is not str or not prompt:
            raise ValueError("Qwen3 chat template must return a string")
        encoded = tokenizer(prompt, add_special_tokens=False)["input_ids"]
        if not 0 < len(encoded) <= max_prompt_tokens:
            raise ValueError(f"prompt would be truncated: {ep.episode_id}")

        gold = {
            "root_cause_id": ep.oracle.root_cause_id,
            "evidence_ids": list(ep.oracle.required_evidence_ids),
            "stop_reason": (
                "verified" if ep.oracle.answerable else "insufficient_evidence"
            ),
        }
        gold_ids = tokenizer(
            json.dumps(gold), add_special_tokens=False,
        )["input_ids"]
        if len(gold_ids) > max_completion_tokens:
            raise ValueError(f"valid answer exceeds completion budget: {ep.episode_id}")
        result.append({"prompt": prompt, "episode_id": ep.episode_id})
    return result
