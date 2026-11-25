"""Exercise the exact-commit verification gate without invoking real CI/GPU."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import shlex

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'verify_exact_tree.py'


def shell(*args, cwd):
    return subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / 'fixture'
    root.mkdir()
    shell('git', 'init', '-q', cwd=root)
    (root / 'pytest.py').write_text('raise SystemExit(0)\n')
    (root / '.gitignore').write_text('__pycache__/\n*.pyc\n')
    (root / 'demo.txt').write_text('original\n')
    shell('git', 'add', '.', cwd=root)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'fixture', cwd=root)
    return root


def invoke(repo, *, sha=None, suite='python', expected_python=None, env=None):
    out = repo.parent / 'evidence'
    args = [sys.executable, str(SCRIPT), '--repo', str(repo), '--expected-sha', sha or shell('git', 'rev-parse', 'HEAD', cwd=repo), '--scope', suite, '--out-dir', str(out)]
    if expected_python is not None:
        args += ['--expected-python', expected_python]
    result = subprocess.run(args, cwd=repo, text=True, capture_output=True, env=env)
    manifest = json.loads((out / 'manifest.json').read_text()) if (out / 'manifest.json').exists() else None
    return result, manifest, out


def test_exact_sha_python_suite_produces_pinned_manifest_and_log(repo):
    proc, receipt, out = invoke(repo)
    assert proc.returncode == 0, proc.stderr
    assert receipt['status'] == 'PASS'
    assert receipt['expected_sha'] == receipt['actual_sha'] == shell('git', 'rev-parse', 'HEAD', cwd=repo)
    assert receipt['scope'] == 'python'
    assert receipt['tracked_tree_clean'] is True
    assert receipt['production_eligible'] is False
    assert len(receipt['checks']) == 1
    step = receipt['checks'][0]
    assert step['name'] == 'python-pytest'
    assert step['return_code'] == 0
    log = (out / step['log_path']).read_bytes()
    assert hashlib.sha256(log).hexdigest() == step['log_sha256']


def test_sha_mismatch_fails_before_test_execution(repo):
    (repo / 'pytest.py').write_text('raise SystemExit(91)\n')
    # Even with dirty tracked bytes, SHA mismatch must abort without running pytest.
    proc, receipt, _ = invoke(repo, sha='0' * 40)
    assert proc.returncode != 0
    assert receipt['status'] == 'HOLD'
    assert receipt['checks'] == []
    assert 'SHA' in receipt['reason']


def test_tracked_worktree_modification_fails_before_test_execution(repo):
    (repo / 'demo.txt').write_text('dirty\n')
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'HOLD'
    assert receipt['checks'] == []
    assert 'dirty' in receipt['reason']


def test_incorrect_python_version_is_hold_not_pass(repo):
    proc, receipt, _ = invoke(repo, expected_python='0.0')
    assert proc.returncode != 0
    assert receipt['status'] == 'HOLD'
    assert receipt['checks'] == []
    assert 'Python' in receipt['reason']


def test_failed_pytest_writes_failure_evidence_and_exit_nonzero(repo):
    (repo / 'pytest.py').write_text('raise SystemExit(7)\n')
    shell('git', 'add', '.', cwd=repo)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'failing', cwd=repo)
    proc, receipt, out = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert receipt['checks'][0]['return_code'] == 7
    assert (out / receipt['checks'][0]['log_path']).is_file()


def test_missing_go_binary_fails_not_skips(repo):
    env = os.environ.copy()
    bindir = repo.parent / 'only-git-bin'
    bindir.mkdir()
    (bindir / 'git').symlink_to(shutil.which('git'))
    env['PATH'] = str(bindir)
    proc, receipt, _ = invoke(repo, suite='go', env=env)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert receipt['checks']
    assert receipt['checks'][0]['return_code'] is None


def test_invalid_expected_sha_does_not_run_commands(repo):
    proc, receipt, _ = invoke(repo, sha='main')
    assert proc.returncode != 0
    assert receipt['status'] == 'HOLD'
    assert receipt['checks'] == []


def test_fail_on_missing_python_test_dependency(repo):
    (repo / 'pytest.py').unlink()
    shell('git', 'add', '-u', cwd=repo)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'remove-stub', cwd=repo)
    # Can't assert test pass; pytest may legitimately exit 5 for no tests.
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert receipt['checks'][0]['return_code'] != 0


def fake_go_environment(repo, *, fail_on=None, create_binary=True, bundle_output=None):
    bindir = repo.parent / 'stub-go-bin'
    bindir.mkdir(exist_ok=True)
    git_path = shutil.which('git')
    assert git_path
    (bindir / 'git').symlink_to(git_path)
    # A successful go build must result in an executable artifact. The
    # original fake Go compiler returned success without producing a file,
    # which exposed the verifier's old go-run false positive.
    built = bindir / 'standalone-sre-agent'
    receipt = (bundle_output if bundle_output is not None else json.dumps({
        'status': 'STRUCTURALLY_VALID', 'bundle_sha256': '0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3',
        'evidence_count': 2, 'supported_hypotheses': 1,
    }) + '\n')
    built.write_text(
        '#!/bin/sh\n'
        f'printf "%s|%s\\n" "$PWD" "$*" >> "{repo.parent / "binary-invocations.txt"}"\n'
        f'printf %s {shlex.quote(receipt)}\n'
        'exit 0\n'
    )
    built.chmod(0o755)
    go = bindir / 'go'
    go.write_text(
        '#!/bin/sh\n'
        f'echo "$*" >> "{repo.parent / "go-invocations.txt"}"\n'
        f'if [ "$1" = "{fail_on or "NEVER"}" ]; then exit 13; fi\n'
        f'if [ "$1" = "build" ] && [ "{"yes" if create_binary else "no"}" = "yes" ]; then /bin/cp "{built}" "$3"; /bin/chmod 755 "$3"; fi\n'
        'exit 0\n'
    )
    go.chmod(0o755)
    env = os.environ.copy()
    env['PATH'] = str(bindir)
    return env


def test_go_scope_executes_race_vet_build_and_bundle_with_logs(repo):
    proc, receipt, out = invoke(repo, suite='go', env=fake_go_environment(repo))
    assert proc.returncode == 0, proc.stderr
    assert receipt['status'] == 'PASS'
    assert [x['name'] for x in receipt['checks']] == [
        'go-race', 'go-vet', 'go-build', 'go-bundle-contract',
    ]
    assert all(x['return_code'] == 0 for x in receipt['checks'])
    commands = (repo.parent / 'go-invocations.txt').read_text().splitlines()
    assert commands[0] == 'test -race ./...'
    assert commands[1] == 'vet ./...'
    assert commands[2].startswith('build -o ')
    assert len(commands) == 3, "the built executable, not go run, must do the smoke check"
    binary = (repo.parent / 'binary-invocations.txt').read_text().splitlines()
    assert binary == [
        f'{out}|verify-bundle --scenario --file '
        f'{repo / "benchmarks/scenarios/checkout-latency.json"}'
    ]
    assert receipt['checks'][3]['argv'][0] == str(out / 'sre-agent')
    for x in receipt['checks']:
        log = (out / x['log_path']).read_bytes()
        assert hashlib.sha256(log).hexdigest() == x['log_sha256']


def test_go_build_success_without_binary_must_not_pass_smoke(repo):
    # Fake Go says build succeeded, yet emits no executable: the old
    # 'go run' smoke incorrectly PASSed without exercising the built artifact.
    proc, receipt, out = invoke(
        repo, suite='go',
        env=fake_go_environment(repo, create_binary=False),
    )
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert [step['name'] for step in receipt['checks']] == [
        'go-race', 'go-vet', 'go-build', 'go-bundle-contract',
    ]
    assert receipt['checks'][-1]['return_code'] is None
    assert not (out / 'sre-agent').exists()


def test_go_failure_stops_remaining_commands_without_claiming_pass(repo):
    proc, receipt, _ = invoke(repo, suite='go', env=fake_go_environment(repo, fail_on='vet'))
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert [x['name'] for x in receipt['checks']] == ['go-race', 'go-vet']
    assert receipt['checks'][-1]['return_code'] == 13
    assert 'go-build' not in [x['name'] for x in receipt['checks']]


def test_untracked_source_blocks_exact_tree_proof(repo):
    (repo / 'rogue.py').write_text('raise RuntimeError("unreviewed code")\n')
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'HOLD'
    assert receipt['checks'] == []
    assert 'untracked' in receipt['reason']


def test_test_command_mutates_tracked_file_so_result_is_not_pass(repo):
    (repo / 'pytest.py').write_text(
        'from pathlib import Path\n'
        'Path("demo.txt").write_text("changed during tests\\n")\n'
        'raise SystemExit(0)\n'
    )
    shell('git', 'add', '.', cwd=repo)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org',
          'commit', '-qm', 'mutating-test', cwd=repo)
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert 'during verification' in receipt['reason']
    assert receipt['post_run_tree_clean'] is False
    assert receipt['checks'][0]['return_code'] == 0


def test_test_command_changes_git_head_so_result_is_not_pass(repo):
    (repo / 'pytest.py').write_text(
        'import subprocess\n'
        'subprocess.run(["git", "-c", "user.name=Test", "-c",'
        ' "user.email=test@example.org", "commit", "--allow-empty",'
        ' "-qm", "unexpected-test-commit"], check=True)\n'
        'raise SystemExit(0)\n'
    )
    shell('git', 'add', '.', cwd=repo)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org',
          'commit', '-qm', 'head-mutating-test', cwd=repo)
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert receipt['actual_sha'] != receipt['post_run_sha']
    assert 'during verification' in receipt['reason']
    assert receipt['checks'][0]['return_code'] == 0


def test_test_command_creates_untracked_file_so_result_is_not_pass(repo):
    (repo / 'pytest.py').write_text(
        'from pathlib import Path\n'
        'Path("unreviewed.py").write_text("print(1)\\n")\n'
        'raise SystemExit(0)\n'
    )
    shell('git', 'add', '.', cwd=repo)
    shell('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org',
          'commit', '-qm', 'untracked-test', cwd=repo)
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    assert receipt['post_run_tree_clean'] is False
    assert 'during verification' in receipt['reason']


# Security regression: evidence artifacts must be create-only. The verifier
# must not overwrite old CI proof or follow a log/manifest symlink even when
# the final Git tree check would later mark a run as FAIL.
def invoke_raw(repo, out, *, sha=None):
    command = [
        sys.executable, str(SCRIPT), "--repo", str(repo),
        "--expected-sha", sha or shell("git", "rev-parse", "HEAD", cwd=repo),
        "--scope", "python", "--out-dir", str(out),
    ]
    return subprocess.run(command, cwd=repo, capture_output=True, text=True)


def test_preexisting_python_log_is_not_overwritten(repo):
    out = repo.parent / "existing-log"
    out.mkdir()
    log = out / "python-pytest.log"
    log.write_bytes(b"independently-preserved-proof")
    result = invoke_raw(repo, out)
    assert result.returncode != 0
    assert log.read_bytes() == b"independently-preserved-proof"


def test_symlinked_python_log_cannot_modify_external_source(repo):
    out = repo.parent / "linked-log"
    out.mkdir()
    external = repo.parent / "protected-source.txt"
    external.write_bytes(b"DO-NOT-MODIFY")
    (out / "python-pytest.log").symlink_to(external)
    result = invoke_raw(repo, out)
    assert result.returncode != 0
    assert external.read_bytes() == b"DO-NOT-MODIFY"


def test_preexisting_manifest_is_not_rewritten(repo):
    out = repo.parent / "existing-manifest"
    out.mkdir()
    manifest = out / "manifest.json"
    manifest.write_bytes(b"earlier-verified-record")
    result = invoke_raw(repo, out, sha="not-a-sha")
    assert result.returncode != 0
    assert manifest.read_bytes() == b"earlier-verified-record"


def test_symlinked_manifest_cannot_modify_external_source(repo):
    out = repo.parent / "linked-manifest"
    out.mkdir()
    external = repo.parent / "protected-manifest-source.txt"
    external.write_bytes(b"DO-NOT-MODIFY")
    (out / "manifest.json").symlink_to(external)
    result = invoke_raw(repo, out, sha="not-a-sha")
    assert result.returncode != 0
    assert external.read_bytes() == b"DO-NOT-MODIFY"


def test_exact_tree_log_and_manifest_are_private_regular_files(repo):
    import stat

    proc, receipt, out = invoke(repo)
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE((out / "manifest.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((out / "python-pytest.log").stat().st_mode) == 0o600
    assert not (out / "manifest.json").is_symlink()
    assert receipt["status"] == "PASS"


@pytest.mark.parametrize("flag", ["assume-unchanged", "skip-worktree"])
def test_hidden_index_flag_blocks_modified_tracked_source(repo, flag):
    shell("git", "update-index", "--" + flag, "demo.txt", cwd=repo)
    (repo / "demo.txt").write_text("hidden modification\n")
    # Demonstrate that ordinary porcelain status misses the modified bytes.
    assert shell("git", "status", "--porcelain", "--untracked-files=normal", cwd=repo) == ""
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt["status"] == "HOLD"
    assert receipt["checks"] == []
    assert "index" in receipt["reason"]


@pytest.mark.parametrize("flag", ["assume-unchanged", "skip-worktree"])
def test_test_command_can_not_hide_tracked_mutation_with_index_flag(repo, flag):
    (repo / "pytest.py").write_text(
        "import subprocess\n"
        "from pathlib import Path\n"
        f"subprocess.run(['git', 'update-index', '--{flag}', 'demo.txt'], check=True)\n"
        "Path('demo.txt').write_text('hidden mutation during tests\\n')\n"
        "raise SystemExit(0)\n"
    )
    shell("git", "add", ".", cwd=repo)
    shell("git", "-c", "user.name=Test", "-c", "user.email=test@example.org",
          "commit", "-qm", "hidden-mutation-test", cwd=repo)
    proc, receipt, _ = invoke(repo)
    assert proc.returncode != 0
    assert receipt["status"] == "FAIL"
    assert receipt["post_run_tree_clean"] is False
    assert receipt["checks"][0]["return_code"] == 0
    assert "during verification" in receipt["reason"]


def test_go_zero_exit_with_no_receipt_must_fail(repo):
    # The built executable may return success without producing a Go result.
    # Exit status alone is insufficient evidence for a checked contract.
    proc, receipt, _ = invoke(repo, suite='go', env=fake_go_environment(repo, bundle_output=''))
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    step = receipt['checks'][-1]
    assert step['name'] == 'go-bundle-contract'
    assert step['return_code'] == 0
    assert 'invalid Go bundle receipt' in step.get('error', '')


@pytest.mark.parametrize("fault", ["wrong_status", "bool_count", "missing_digest", "duplicate", "trailing"])
def test_go_zero_exit_with_invalid_receipt_must_fail(repo, fault):
    payload = {'status': 'STRUCTURALLY_VALID', 'bundle_sha256': '0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3',
               'evidence_count': 2, 'supported_hypotheses': 1}
    if fault == "wrong_status":
        payload["status"] = "INVALID"
    elif fault == "bool_count":
        payload["evidence_count"] = True
    elif fault == "missing_digest":
        payload["bundle_sha256"] = "a" * 63
    raw = json.dumps(payload) + "\n"
    if fault == "duplicate":
        raw = '{"status":"STRUCTURALLY_VALID",' + raw[1:]
    elif fault == "trailing":
        raw += "{}\n"
    proc, receipt, _ = invoke(repo, suite='go',
                              env=fake_go_environment(repo, bundle_output=raw))
    assert proc.returncode != 0
    assert receipt['status'] == 'FAIL'
    step = receipt['checks'][-1]
    assert step['name'] == 'go-bundle-contract'
    assert step['return_code'] == 0
    assert 'invalid Go bundle receipt' in step.get('error', '')


@pytest.mark.parametrize("fake_digest", ["a" * 64, "0" * 64])
def test_go_contract_rejects_wrong_well_formed_digest(repo, fake_digest):
    # A structurally correct success receipt cannot claim an arbitrary SHA.
    response = json.dumps({
        "status": "STRUCTURALLY_VALID", "bundle_sha256": fake_digest,
        "evidence_count": 2, "supported_hypotheses": 1,
    }) + "\n"
    proc, receipt, _ = invoke(
        repo, suite="go", env=fake_go_environment(repo, bundle_output=response))
    assert proc.returncode != 0
    assert receipt["status"] == "FAIL"
    assert receipt["checks"][-1]["return_code"] == 0
    assert "invalid Go bundle receipt" in receipt["checks"][-1].get("error", "")


def test_pinned_checkout_digest_matches_committed_fixture():
    # Independently matches internal/evidence/bundle_test.go TestLegacy...
    fixture = SCRIPT.parents[1] / "benchmarks/scenarios/checkout-latency.json"
    scenario = json.loads(fixture.read_text(encoding="utf-8"))
    bundle = scenario["bundle"]
    bundle["metadata"].pop("bundle_sha256", None)
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == "0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3"
