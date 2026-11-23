"""NetworkPolicy G2i lab intake must never promote admin truth into Observer prompt."""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from agentic_aiops.grpo_lab_intake import import_networkpolicy_lab_candidate
from agentic_aiops.grpo_training import build_prompt, load_episodes


PHASES = ("before", "during", "after")
SNAPSHOTS = ("pod", "probe", "service", "endpoint_slices", "network_policy_list")


def write(path: Path, obj: object) -> str:
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(raw: bytes) -> dict:
    return {
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_response_base64": base64.b64encode(raw).decode("ascii"),
    }


def make_fixture(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    bundle = {"schema_version": "sre.networkpolicy-oracle/v1",
              "episode_id": "np-calico-egress-001"}
    observer_hashes = {}
    for phase in PHASES:
        good = phase != "during"
        probe = {
            "schema_version": "sre.dns-probe/v1",
            "host": "checkout-api.golden-demo.svc.cluster.local",
            "service_ip": "10.96.0.20",
            "resolver": "nameserver 10.96.0.10",
            "dns_ok": True, "dns_addresses": ["10.96.0.20"],
            "dns_error": "",
            "name_http_status": 200 if good else 0,
            "direct_http_status": 200 if good else 0,
            "direct_http_attempts": [200, 200, 200] if good else [0, 0, 0],
            "direct_http_errors": ["", "", ""],
        }
        raw = (json.dumps(probe, sort_keys=True) + "\n").encode()
        (root / f"{phase}-admin.log").write_bytes(raw)
        (root / f"{phase}-observer.log").write_bytes(raw)
        observer_hashes[phase] = hashlib.sha256(raw).hexdigest()
        observation = {
            "schema_version": "sre.dns-observation/v1",
            "host": probe["host"],
            "service_ip": probe["service_ip"],
            "classification": "HEALTHY_NAME_AND_IP" if good else "UNKNOWN",
            "observed": snapshot(raw),
        }
        write(root / f"{phase}-observation.json", observation)
        bundle[phase] = {
            key: snapshot(raw if key == "probe" else
                          (json.dumps({"phase": phase, "kind": key}) + "\n").encode())
            for key in SNAPSHOTS
        }
    bundle_sha = write(root / "episode.json", bundle)
    evaluation = {
        "schema_version": "sre.networkpolicy-evaluation/v1",
        "episode_id": "np-calico-egress-001",
        "status": "MATCHED_LAB_NETWORK_POLICY_DENIAL",
        "before_diagnostic": "HEALTHY_NAME_AND_IP",
        "during_diagnostic": "UNKNOWN",
        "after_diagnostic": "HEALTHY_NAME_AND_IP",
        "production_causality_verified": False,
        "explanation": "bounded Calico lab, not production",
    }
    eval_sha = write(root / "evaluation.json", evaluation)
    approval = {
        "schema_version": "sre.grpo.networkpolicy-lab-approval/v1",
        "episode_id": "np-calico-egress-001",
        "output_episode_id": "lab-np-001",
        "fault_family": "network-egress-unknown",
        "split": "test",
        "episode_sha256": bundle_sha,
        "evaluation_sha256": eval_sha,
        "observer_log_sha256": observer_hashes,
    }
    approval_file = tmp_path / "approval.json"
    approval_sha = write(approval_file, approval)
    return root, approval_file, approval_sha


def intake(root, approval, digest, out):
    return import_networkpolicy_lab_candidate(
        root, approval, expected_approval_sha256=digest, output=out
    )


def test_g2i_candidate_only_exposes_readonly_observer_and_abstains(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "lab-episode.jsonl"
    receipt = intake(root, approval, digest, output)
    ep, = load_episodes(output)
    assert ep.oracle.answerable is False
    assert ep.oracle.root_cause_id == "unknown"
    assert ep.oracle.required_evidence_ids == ()
    assert ep.split == "test"
    assert len(ep.observations) == 2  # before + during; no after-fault peek
    assert all(o.tool == "kubernetes.get_logs" for o in ep.observations)
    prompt = build_prompt(ep)
    assert "before" in prompt and "during" in prompt
    assert "after" not in prompt
    assert "MATCHED_LAB_NETWORK_POLICY_DENIAL" not in prompt
    assert "NetworkPolicy" not in prompt
    assert "admin" not in prompt
    assert receipt["lab_claim_authenticated"] is False
    assert receipt["training_admission_authorized"] is False
    assert receipt["source_classification"] == "unverified-lab-candidate"
    assert receipt["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()


def test_missing_pin_and_modified_evaluation_never_emit(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    with pytest.raises(ValueError, match="approval_sha256"):
        intake(root, approval, "0" * 64, output)
    assert not output.exists()
    evaluation = json.loads((root / "evaluation.json").read_text())
    evaluation["status"] = "PASS"
    write(root / "evaluation.json", evaluation)
    with pytest.raises(ValueError, match="evaluation_sha256"):
        intake(root, approval, digest, output)
    assert not output.exists()


def test_raw_observer_tamper_rejected(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    (root / "during-observer.log").write_text("{}\n")
    with pytest.raises(ValueError, match="observer_log_sha256"):
        intake(root, approval, digest, output)
    assert not output.exists()


def test_matching_admin_and_observer_replays_are_required(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    (root / "during-admin.log").write_text("{}\n")
    with pytest.raises(ValueError, match="admin.*observer"):
        intake(root, approval, digest, output)
    assert not output.exists()


def test_snapshot_digest_and_observation_consistency_required(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    obs = json.loads((root / "during-observation.json").read_text())
    obs["classification"] = "NETWORK_POLICY_CONFIRMED"
    write(root / "during-observation.json", obs)
    with pytest.raises(ValueError, match="classification"):
        intake(root, approval, digest, output)
    assert not output.exists()


def test_missing_or_malformed_phase_snapshot_rejected(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    episode = json.loads((root / "episode.json").read_text())
    episode["during"]["pod"]["response_sha256"] = "0" * 64
    # Even a fully re-hashed replacement must not bypass independent approval.
    write(root / "episode.json", episode)
    with pytest.raises(ValueError, match="episode_sha256"):
        intake(root, approval, digest, output)
    assert not output.exists()


def test_conflicting_approval_and_overwrite_rejected(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "out.jsonl"
    intake(root, approval, digest, output)
    frozen = output.read_bytes()
    with pytest.raises(FileExistsError):
        intake(root, approval, digest, output)
    assert output.read_bytes() == frozen
    raw = json.loads(approval.read_text())
    raw["split"] = "train"
    altered_sha = write(approval, raw)
    with pytest.raises(ValueError, match="holdout"):
        intake(root, approval, altered_sha, tmp_path / "another.jsonl")


def test_duplicate_json_keys_fail_even_if_rehashed(tmp_path):
    root, approval, _ = make_fixture(tmp_path)
    raw = approval.read_text().rstrip()
    altered = raw[:-1] + ', "split":"test"}\n'
    approval.write_text(altered)
    digest = hashlib.sha256(approval.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="duplicate"):
        intake(root, approval, digest, tmp_path / "out.jsonl")


def test_g2i_cli_stages_candidate_without_leaking_admin_verdict(tmp_path):
    import subprocess
    import sys

    root, approval, digest = make_fixture(tmp_path)
    output = tmp_path / "candidate.jsonl"
    script = Path(__file__).resolve().parents[1] / "scripts/import_g2i_lab_candidate.py"
    result = subprocess.run(
        [sys.executable, str(script), "--root", str(root),
         "--approval", str(approval),
         "--expected-approval-sha256", digest,
         "--output", str(output)],
        cwd=script.parents[1], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["training_admission_authorized"] is False
    assert receipt["lab_claim_authenticated"] is False
    assert "MATCHED_LAB_NETWORK_POLICY_DENIAL" not in result.stdout
    assert output.is_file()
    again = subprocess.run(
        [sys.executable, str(script), "--root", str(root),
         "--approval", str(approval),
         "--expected-approval-sha256", digest,
         "--output", str(output)],
        cwd=script.parents[1], capture_output=True, text=True, check=False,
    )
    assert again.returncode != 0


def test_even_approved_admin_diagnosis_cannot_upgrade_unknown(tmp_path):
    root, approval, _ = make_fixture(tmp_path)
    payload = json.loads(approval.read_text())
    payload["oracle"] = {
        "answerable": True, "root_cause_id": "network_policy_denied",
        "required_evidence_ids": ["np-during-observer"]
    }
    digest = write(approval, payload)
    with pytest.raises(ValueError, match="fields"):
        intake(root, approval, digest, tmp_path / "out.jsonl")


def test_rehashed_non_object_native_source_rejected(tmp_path):
    root, approval, _ = make_fixture(tmp_path)
    episode = json.loads((root / "episode.json").read_text())
    episode["during"]["pod"] = snapshot(b'["not", "a", "pod"]')
    data_sha = write(root / "episode.json", episode)
    approval_data = json.loads(approval.read_text())
    approval_data["episode_sha256"] = data_sha
    approved_sha = write(approval, approval_data)
    with pytest.raises(ValueError, match="snapshot JSON object"):
        intake(root, approval, approved_sha, tmp_path / "out.jsonl")


def test_rehashed_contradictory_probe_and_original_logs_rejected(tmp_path):
    root, approval, _ = make_fixture(tmp_path)
    probe = json.loads((root / "during-observer.log").read_text())
    probe["name_http_status"] = 200
    probe["direct_http_status"] = 200
    probe["direct_http_attempts"] = [200, 200, 200]
    raw = (json.dumps(probe, sort_keys=True) + "\n").encode()
    (root / "during-admin.log").write_bytes(raw)
    (root / "during-observer.log").write_bytes(raw)
    observation = json.loads((root / "during-observation.json").read_text())
    observation["observed"] = snapshot(raw)
    write(root / "during-observation.json", observation)
    episode = json.loads((root / "episode.json").read_text())
    episode["during"]["probe"] = snapshot(raw)
    episode_sha = write(root / "episode.json", episode)
    approval_data = json.loads(approval.read_text())
    approval_data["episode_sha256"] = episode_sha
    approval_data["observer_log_sha256"]["during"] = hashlib.sha256(raw).hexdigest()
    approved_sha = write(approval, approval_data)
    with pytest.raises(ValueError, match="probe HTTP phases"):
        intake(root, approval, approved_sha, tmp_path / "out.jsonl")


def test_symlinked_observer_source_is_not_accepted(tmp_path):
    root, approval, digest = make_fixture(tmp_path)
    (root / "during-observer.log").unlink()
    (root / "during-observer.log").symlink_to(root / "during-admin.log")
    with pytest.raises(ValueError, match="symlink"):
        intake(root, approval, digest, tmp_path / "out.jsonl")
