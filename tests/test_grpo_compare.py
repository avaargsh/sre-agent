"""Blind holdout A/B/C scoring: exact pinned inputs and paired outcomes.

CPU-only synthetic fixtures verify accounting, never real-model identity.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_aiops.grpo_compare import compare_pinned_holdout


ROOT = Path(__file__).resolve().parents[1]


def ep(eid, family, *, answerable, split="test"):
    return {
        "schema_version": "sre.grpo.episode/v1", "episode_id": eid,
        "fault_family": family, "split": split,
        "alert": f"Alert {family}",
        "observations": [{
            "evidence_id": "ev1", "tool": "prometheus.query",
            "text": f"Original evidence {family}",
        }],
        "oracle": {
            "answerable": answerable,
            "root_cause_id": f"cause_{family}" if answerable else "unknown",
            "required_evidence_ids": ["ev1"] if answerable else [],
        },
    }


def answer(root, refs=None, stop="verified"):
    return json.dumps({
        "root_cause_id": root,
        "evidence_ids": ["ev1"] if refs is None else refs,
        "stop_reason": stop,
    })


def write(path, rows):
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in rows),
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path):
    ds = tmp_path / "episodes.jsonl"
    base = tmp_path / "base.jsonl"
    sft = tmp_path / "sft.jsonl"
    grpo = tmp_path / "grpo.jsonl"
    rows = [
        ep("train-1", "train_fault", answerable=True, split="train"),
        ep("case-1", "memory", answerable=True),
        ep("case-2", "network", answerable=True),
        ep("case-3", "unresolved", answerable=False),
        ep("case-4", "storage", answerable=True),
    ]
    ds_sha = write(ds, rows)
    good = {
        "case-1": answer("cause_memory"),
        "case-2": answer("cause_network"),
        "case-3": answer("unknown", [], "insufficient_evidence"),
        "case-4": answer("cause_storage"),
    }
    wrong = answer("unsupported_cause")
    abstain = answer("unknown", [], "insufficient_evidence")
    cases = {
        "Base": {"case-1": good["case-1"], "case-2": wrong,
                 "case-3": wrong, "case-4": good["case-4"]},
        "SFT": {"case-1": good["case-1"], "case-2": good["case-2"],
                "case-3": wrong, "case-4": wrong},
        "GRPO": {"case-1": good["case-1"], "case-2": good["case-2"],
                 "case-3": abstain, "case-4": wrong},
    }
    digests = {}
    for label, path in [("Base", base), ("SFT", sft), ("GRPO", grpo)]:
        digests[label] = write(path, [
            {"episode_id": eid, "completion": cases[label][eid]}
            for eid in reversed(sorted(cases[label]))
        ])
    return ds, {"Base": base, "SFT": sft, "GRPO": grpo}, ds_sha, digests


def compare(tmp_path, *, expected_dataset_sha=None, expected_prediction_sha=None):
    dataset, files, dataset_sha, digests = fixture(tmp_path)
    return compare_pinned_holdout(
        dataset, prediction_files=files,
        expected_dataset_sha256=expected_dataset_sha or dataset_sha,
        expected_prediction_sha256=expected_prediction_sha or digests,
        split="test",
    )


def test_paired_metrics_show_wins_losses_ties_instead_of_claiming_success(tmp_path):
    report = compare(tmp_path)
    assert report["schema_version"] == "sre.grpo.paired-holdout/v1"
    assert report["cases"] == 4
    assert report["models"]["Base"]["exact_successes"] == 2
    assert report["models"]["SFT"]["exact_successes"] == 2
    assert report["models"]["GRPO"]["exact_successes"] == 3
    # On same cases GRPO beats Base twice (case-2, case-3)
    # but loses once on case-4; case-1 is a tie.
    paired = report["paired"]["GRPO_vs_Base"]
    assert paired["win"] == 2
    assert paired["loss"] == 1
    assert paired["tie_both_correct"] == 1
    assert paired["tie_both_incorrect"] == 0
    assert paired["exact_success_rate_delta"] == pytest.approx(0.25)
    assert report["models"]["GRPO"]["correct_abstention_rate"] == 1.0
    assert report["model_runtime_verified"] is False
    assert report["model_attribution_verified"] is False
    assert report["superiority_claim_authorized"] is False
    assert report["production_eligible"] is False
    assert report["paired"]["GRPO_vs_SFT"]["win"] == 1
    assert report["paired"]["GRPO_vs_SFT"]["loss"] == 0


def test_reject_unpinned_or_mismatched_dataset_or_prediction(tmp_path):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    with pytest.raises(ValueError, match="dataset_sha256"):
        compare_pinned_holdout(
            dataset, prediction_files=files,
            expected_dataset_sha256="0"*64,
            expected_prediction_sha256=shas,
        )
    with pytest.raises(ValueError, match="GRPO.*sha256"):
        compare_pinned_holdout(
            dataset, prediction_files=files,
            expected_dataset_sha256=ds_sha,
            expected_prediction_sha256={**shas, "GRPO": "0"*64},
        )


def test_incomplete_extra_and_train_predictions_rejected(tmp_path):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    grpo = files["GRPO"]
    for bad in (
        [{"episode_id": "case-1", "completion": answer("cause_memory")}],
        [{"episode_id": "train-1", "completion": answer("cause_train_fault")}],
        [{"episode_id": "fabricated", "completion": "{}"}],
    ):
        sha = write(grpo, bad)
        with pytest.raises(ValueError, match="missing|unexpected"):
            compare_pinned_holdout(
                dataset, prediction_files=files,
                expected_dataset_sha256=ds_sha,
                expected_prediction_sha256={**shas, "GRPO": sha},
            )


def test_all_models_same_file_or_missing_required_model_rejected(tmp_path):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    with pytest.raises(ValueError, match="distinct"):
        compare_pinned_holdout(
            dataset, prediction_files={**files, "GRPO": files["Base"]},
            expected_dataset_sha256=ds_sha,
            expected_prediction_sha256=shas,
        )
    with pytest.raises(ValueError, match="Base.*SFT.*GRPO"):
        compare_pinned_holdout(
            dataset, prediction_files={"Base": files["Base"], "GRPO": files["GRPO"]},
            expected_dataset_sha256=ds_sha,
            expected_prediction_sha256={"Base": shas["Base"], "GRPO": shas["GRPO"]},
        )


def test_dataset_sha_verified_against_same_bytes_used_to_parse(tmp_path, monkeypatch):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    original = Path.read_bytes
    reads = []

    def traced_read(p):
        if p == dataset:
            reads.append(1)
        return original(p)

    monkeypatch.setattr(Path, "read_bytes", traced_read)
    result = compare_pinned_holdout(
        dataset, prediction_files=files,
        expected_dataset_sha256=ds_sha,
        expected_prediction_sha256=shas,
    )
    assert result["cases"] == 4
    assert len(reads) == 1


def test_duplicate_oracle_and_identical_predictions_do_not_imply_superiority(tmp_path):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    files["GRPO"].write_bytes(files["Base"].read_bytes())
    shas["GRPO"] = hashlib.sha256(files["GRPO"].read_bytes()).hexdigest()
    report = compare_pinned_holdout(
        dataset, prediction_files=files,
        expected_dataset_sha256=ds_sha,
        expected_prediction_sha256=shas,
    )
    assert report["paired"]["GRPO_vs_Base"]["win"] == 0
    assert report["paired"]["GRPO_vs_Base"]["loss"] == 0
    assert report["paired"]["GRPO_vs_Base"]["exact_success_rate_delta"] == 0.0
    assert report["superiority_claim_authorized"] is False


def test_cli_prints_fail_closed_nonpromotion_flags_without_exposing_oracle(tmp_path):
    dataset, files, ds_sha, shas = fixture(tmp_path)
    script = ROOT / "scripts/compare_sre_grpo_holdout.py"
    cmd = [
        sys.executable, str(script),
        "--dataset", str(dataset), "--expected-dataset-sha256", ds_sha,
        "--base", str(files["Base"]), "--base-sha256", shas["Base"],
        "--sft", str(files["SFT"]), "--sft-sha256", shas["SFT"],
        "--grpo", str(files["GRPO"]), "--grpo-sha256", shas["GRPO"],
        "--split", "test",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["cases"] == 4
    assert report["superiority_claim_authorized"] is False
    assert "cause_network" not in result.stdout
    cmd[cmd.index("--base-sha256") + 1] = "0" * 64
    failed = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    assert failed.returncode == 3
    assert "UNKNOWN" in failed.stderr
