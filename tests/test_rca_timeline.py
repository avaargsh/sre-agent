import json
from copy import deepcopy

import pytest

from agentic_aiops.report import render_rca_json


def evidence(event_id, timestamp):
    return {"evidence_id": event_id, "source": "metrics", "observation": "latency", "timestamp": timestamp}


def change(event_id, timestamp):
    return {"change_id": event_id, "entity_id": "checkout", "kind": "deployment", "summary": "rollout", "timestamp": timestamp}


def bundle(evidence_items=(), changes=()):
    return {
        "incident": {"incident_id": "inc-1", "summary": "latency", "severity": "sev2"},
        "evidence": list(evidence_items),
        "changes": list(changes),
    }


def test_timeline_orders_observations_and_changes_by_actual_time():
    data = bundle(
        [evidence("late", "2026-11-25T13:01:00+08:00"), evidence("early", "2026-11-25T05:00:00.000000001Z")],
        [change("middle", "2026-11-25T05:00:00.000000002Z")],
    )
    original = deepcopy(data)
    report = json.loads(render_rca_json(data))
    assert [event["event_id"] for event in report["timeline"]] == ["early", "middle", "late"]
    assert report["timeline"][1]["event_type"] == "change"
    assert report["timeline"][1]["entity_id"] == "checkout"
    assert report["timeline"][1]["summary"] == "rollout"
    assert report["timeline"][2]["timestamp"] == "2026-11-25T13:01:00+08:00"
    assert report["undated_events"] == []
    assert report["independently_verified"] is False
    assert report["execution_authorized"] is False
    assert data == original


def test_timeline_keeps_equal_times_stable_without_inferring_causality():
    data = bundle([evidence("e", "2026-11-25T13:00:00+08:00")], [change("c", "2026-11-25T05:00:00Z")])
    report = json.loads(render_rca_json(data))
    assert [event["event_id"] for event in report["timeline"]] == ["e", "c"]
    assert all(event["timestamp_status"] == "parsed" for event in report["timeline"])


@pytest.mark.parametrize("timestamp", ["2026-11-25T05:00:00", "2026-02-30T05:00:00Z", "2026-11-25T05:00:00+00:60", "2026-11-25T05:00:00.1234567890Z", 123, ""])
def test_invalid_timestamps_stay_out_of_chronological_timeline(timestamp):
    report = json.loads(render_rca_json(bundle([evidence("bad", timestamp)])))
    assert report["timeline"] == []
    event, = report["undated_events"]
    assert event["event_id"] == "bad"
    assert event["timestamp"] == timestamp
    assert event["timestamp_status"] == "invalid"


def test_missing_timestamps_and_empty_bundle():
    report = json.loads(render_rca_json(bundle([evidence("missing", None)], [change("missing-change", None)])))
    assert report["timeline"] == []
    assert [event["event_id"] for event in report["undated_events"]] == ["missing", "missing-change"]
    assert all(event["timestamp_status"] == "missing" for event in report["undated_events"])
    empty = json.loads(render_rca_json(bundle()))
    assert empty["timeline"] == empty["undated_events"] == []
