"""CPU-only Oracle-free Holdout projection and independent exact-byte replay.

No GPU/model imports, no sampler, no Adapter and no production authorization.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_aiops.grpo_holdout_projection as projection
from agentic_aiops.grpo_holdout_projection import (
    project_holdout_prompts,
    verify_holdout_projection,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "benchmarks/grpo/synthetic-episodes.jsonl"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixtures(tmp_path):
    dataset = tmp_path / "episodes.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    prompts = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "projection.json"
    report = project_holdout_prompts(
        dataset,
        expected_dataset_sha256=sha(dataset),
        split="test",
        output=prompts,
        manifest=manifest,
    )
    pins = {
        "expected_dataset_sha256": sha(dataset),
        "expected_prompts_sha256": sha(prompts),
        "expected_manifest_sha256": sha(manifest),
    }
    return dataset, prompts, manifest, report, pins


def test_projection_excludes_private_oracle_and_train_cases(tmp_path):
    dataset, prompts, manifest, report, pins = fixtures(tmp_path)
    rows = [json.loads(line) for line in prompts.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["episode_id"] == "synthetic-unresolved-001"
    assert set(rows[0]) == {"episode_id", "prompt"}
    for confidential in ("oom_killed", '"oracle"', "synthetic-pod-oom-001"):
        assert confidential not in prompts.read_text()
    assert report["oracle_in_projection"] is False
    assert report["model_runtime_verified"] is False
    assert report["training_admission_authorized"] is False
    assert report == json.loads(manifest.read_text())
    verified = verify_holdout_projection(dataset, prompts, manifest, **pins)
    assert verified["oracle_free_projection_verified"] is True
    assert verified["exact_projection_bytes_verified"] is True
    assert verified["data_issuer_authenticated"] is False
    assert verified["model_attribution_verified"] is False
    assert verified["production_eligible"] is False


def test_replay_does_not_modify_source_artifacts(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    snapshots = [path.read_bytes() for path in (dataset, prompts, manifest)]
    for _ in range(2):
        verify_holdout_projection(dataset, prompts, manifest, **pins)
    assert snapshots == [path.read_bytes() for path in (dataset, prompts, manifest)]


def test_changed_projection_fails_even_when_all_hashes_recomputed(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    rows = [json.loads(line) for line in prompts.read_text().splitlines()]
    rows[0]["prompt"] += "\nPrivate Oracle: fabricated-cause"
    prompts.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows), encoding="utf-8",
    )
    new_manifest = json.loads(manifest.read_text())
    new_manifest["prompts_sha256"] = sha(prompts)
    manifest.write_text(json.dumps(new_manifest, sort_keys=True) + "\n")
    pins["expected_prompts_sha256"] = sha(prompts)
    pins["expected_manifest_sha256"] = sha(manifest)
    with pytest.raises(ValueError, match="recomputed Oracle-free"):
        verify_holdout_projection(dataset, prompts, manifest, **pins)


@pytest.mark.parametrize("field,forged", [
    ("oracle_in_projection", True),
    ("model_runtime_verified", True),
    ("training_admission_authorized", True),
    ("source_classification", "PRODUCTION_VERIFIED"),
    ("cases", 999),
    ("cases", True),  # Python bool compares equal to int 1.
    ("oracle_in_projection", 0),  # Python 0 compares equal to False.
    ("model_runtime_verified", 0),
    ("training_admission_authorized", 0),
])
def test_forged_manifest_fails_even_with_new_sha_pin(tmp_path, field, forged):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    data = json.loads(manifest.read_text())
    data[field] = forged
    manifest.write_text(json.dumps(data, sort_keys=True) + "\n")
    pins["expected_manifest_sha256"] = sha(manifest)
    with pytest.raises(ValueError, match="manifest claims"):
        verify_holdout_projection(dataset, prompts, manifest, **pins)


def test_unknown_manifest_fields_rejected(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    data = json.loads(manifest.read_text())
    data["production_release_authorized"] = True
    manifest.write_text(json.dumps(data) + "\n")
    pins["expected_manifest_sha256"] = sha(manifest)
    with pytest.raises(ValueError, match="fields"):
        verify_holdout_projection(dataset, prompts, manifest, **pins)


def test_missing_or_symlinked_artifact_fails_closed(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    link = tmp_path / "prompts-link.jsonl"
    link.symlink_to(prompts)
    with pytest.raises(ValueError, match="holdout prompts symlink rejected"):
        verify_holdout_projection(dataset, link, manifest, **pins)
    manifest.unlink()
    with pytest.raises(FileNotFoundError):
        verify_holdout_projection(dataset, prompts, manifest, **pins)


def test_wrong_dataset_pin_and_train_split_cannot_publish(tmp_path):
    dataset = tmp_path / "dataset.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    output = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "manifest.json"
    with pytest.raises(ValueError, match="dataset_sha256"):
        project_holdout_prompts(
            dataset, expected_dataset_sha256="0" * 64,
            output=output, manifest=manifest,
        )
    with pytest.raises(ValueError, match="split"):
        project_holdout_prompts(
            dataset, expected_dataset_sha256=sha(dataset),
            split="train", output=output, manifest=manifest,
        )
    assert not output.exists() and not manifest.exists()


def test_oversized_dataset_rejected_without_read_all(tmp_path, monkeypatch):
    dataset = tmp_path / "large.jsonl"
    with dataset.open("wb") as stream:
        stream.truncate(4 * 1024 * 1024 + 1)
    def forbidden(_path):
        raise AssertionError("unbounded Path.read_bytes called")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    with pytest.raises(ValueError, match="holdout dataset must be a bounded regular file"):
        project_holdout_prompts(
            dataset, expected_dataset_sha256="0" * 64,
            output=tmp_path / "prompts.jsonl",
            manifest=tmp_path / "projection.json",
        )
    assert not (tmp_path / "prompts.jsonl").exists()


def test_second_publication_failure_rolls_back_owned_output(tmp_path, monkeypatch):
    dataset = tmp_path / "dataset.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    output = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "projection.json"
    original = projection.os.link

    def failing_manifest_link(source, target, *args, **kwargs):
        if Path(target) == manifest:
            raise OSError("injected second-link failure")
        return original(source, target, *args, **kwargs)

    monkeypatch.setattr(projection.os, "link", failing_manifest_link)
    with pytest.raises(OSError, match="injected second-link failure"):
        project_holdout_prompts(
            dataset, expected_dataset_sha256=sha(dataset),
            output=output, manifest=manifest,
        )
    assert not output.exists() and not manifest.exists()
    assert not list(tmp_path.glob(".sre-grpo-*.stage"))


def test_existing_projection_is_never_overwritten(tmp_path):
    dataset = tmp_path / "dataset.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    target = tmp_path / "prompts.jsonl"
    target.write_bytes(b"existing reviewed bytes")
    with pytest.raises(FileExistsError):
        project_holdout_prompts(
            dataset, expected_dataset_sha256=sha(dataset),
            output=target, manifest=tmp_path / "manifest.json",
        )
    assert target.read_bytes() == b"existing reviewed bytes"


def test_projection_replay_cli_green_and_failclosed_unknown(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    base = [
        sys.executable, str(ROOT / "scripts/verify_sre_grpo_projection.py"),
        "--dataset", str(dataset),
        "--prompts", str(prompts),
        "--manifest", str(manifest),
        "--expected-dataset-sha256", pins["expected_dataset_sha256"],
        "--expected-prompts-sha256", pins["expected_prompts_sha256"],
        "--expected-manifest-sha256", pins["expected_manifest_sha256"],
    ]
    success = subprocess.run(base, cwd=ROOT, capture_output=True, text=True)
    assert success.returncode == 0, success.stderr
    audit = json.loads(success.stdout)
    assert audit["exact_projection_bytes_verified"] is True
    assert audit["production_eligible"] is False
    tampered = base[:]
    tampered[tampered.index("--expected-prompts-sha256") + 1] = "0" * 64
    failure = subprocess.run(tampered, cwd=ROOT, capture_output=True, text=True)
    assert failure.returncode == 3
    assert "UNKNOWN" in failure.stderr


def test_symlinked_source_is_rejected_before_projection(tmp_path):
    dataset = tmp_path / "episodes.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    alias = tmp_path / "alias.jsonl"
    alias.symlink_to(dataset)
    prompts = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "projection.json"
    with pytest.raises(ValueError, match="holdout dataset symlink rejected"):
        project_holdout_prompts(
            alias, expected_dataset_sha256=sha(dataset),
            output=prompts, manifest=manifest,
        )
    assert not prompts.exists() and not manifest.exists()


def test_projection_rejects_symlinked_parent_component_before_read(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    dataset = real_parent / "episodes.jsonl"
    dataset.write_bytes(SAMPLE.read_bytes())
    alias_parent = tmp_path / "alias"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    prompts = tmp_path / "prompts.jsonl"
    manifest = tmp_path / "projection.json"

    with pytest.raises(ValueError, match="symlink|component"):
        project_holdout_prompts(
            alias_parent / dataset.name,
            expected_dataset_sha256=sha(dataset),
            output=prompts, manifest=manifest,
        )
    assert not prompts.exists() and not manifest.exists()


def test_projection_replay_rejects_parent_symlink_and_hardlink_alias(tmp_path):
    dataset, prompts, manifest, _, pins = fixtures(tmp_path)
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    moved_dataset = real_parent / dataset.name
    dataset.replace(moved_dataset)
    alias_parent = tmp_path / "alias"
    alias_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink|component"):
        verify_holdout_projection(
            alias_parent / dataset.name, prompts, manifest, **pins,
        )

    # Even different path names are not independent artifacts if they share
    # one inode. The verifier must detect that before checking the second pin.
    hardlink = tmp_path / "dataset-hardlink.jsonl"
    os.link(moved_dataset, hardlink)
    with pytest.raises(ValueError, match="distinct"):
        verify_holdout_projection(
            moved_dataset, hardlink, manifest, **pins,
        )
