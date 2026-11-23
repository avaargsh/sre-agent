"""Exercise the exact-commit verification gate without invoking real CI/GPU."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil

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


def fake_go_environment(repo, *, fail_on=None):
    bindir = repo.parent / 'stub-go-bin'
    bindir.mkdir(exist_ok=True)
    git_path = shutil.which('git')
    assert git_path
    (bindir / 'git').symlink_to(git_path)
    go = bindir / 'go'
    go.write_text(
        '#!/bin/sh\n'
        f'echo "$*" >> "{repo.parent / "go-invocations.txt"}"\n'
        f'if [ "$1" = "{fail_on or "NEVER"}" ]; then exit 13; fi\n'
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
    assert commands[3].startswith('run ./cmd/sre-agent verify-bundle --scenario --file')
    for x in receipt['checks']:
        log = (out / x['log_path']).read_bytes()
        assert hashlib.sha256(log).hexdigest() == x['log_sha256']


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
