"""Fail closed on inconsistent and unauthenticated exact-head CI artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'verify_ci_evidence_bundle.py'
SHA = 'a' * 40


def receipt(step, argv):
    return {
        'name': step, 'argv': argv, 'return_code': 0,
        'log_path': step + '.log', 'log_sha256': None,
        'duration_ms': 15,
    }


def scope_steps(scope):
    if scope == 'python':
        return [receipt('python-pytest', ['/usr/bin/python', '-m', 'pytest', '-q'])]
    return [
        receipt('go-race', ['go', 'test', '-race', './...']),
        receipt('go-vet', ['go', 'vet', './...']),
        receipt('go-build', ['go', 'build', '-o', '/tmp/sre-exact-go/sre-agent', './cmd/sre-agent']),
        receipt('go-bundle-contract', ['/tmp/sre-exact-go/sre-agent', 'verify-bundle', '--scenario', '--file', '/checkout/benchmarks/scenarios/checkout-latency.json']),
    ]


def artifact(root, name, scope, py_version):
    folder = root / name
    folder.mkdir()
    manifest = {
        'schema_version': 'sre.exact-tree-verification/v1',
        'scope': scope, 'expected_sha': SHA, 'actual_sha': SHA,
        'post_run_sha': SHA, 'tracked_tree_clean': True,
        'post_run_tree_clean': True, 'python_version': py_version,
        'status': 'PASS', 'production_eligible': False,
        'checks': scope_steps(scope),
    }
    for step in manifest['checks']:
        log = (step['name'] + ' output\n').encode()
        if step['name'] == 'go-bundle-contract':
            log = (json.dumps({
                'status': 'STRUCTURALLY_VALID',
                'bundle_sha256': '0e252e0f661ee568ddb02a27db3785c225a1b0386e0d697930c03e10298d5ad3',
                'evidence_count': 2, 'supported_hypotheses': 1,
            }) + '\n').encode()
        (folder / step['log_path']).write_bytes(log)
        step['log_sha256'] = hashlib.sha256(log).hexdigest()
    (folder / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
    return folder


@pytest.fixture
def fixtures(tmp_path):
    result = {
        'python311': artifact(tmp_path, 'py311', 'python', '3.11'),
        'python312': artifact(tmp_path, 'py312', 'python', '3.12'),
        'go': artifact(tmp_path, 'go', 'go', '3.12'),
    }
    return result


def invoke(fixtures, *, sha=SHA):
    out = fixtures['python311'].parent / 'combined.json'
    cmd = [sys.executable, str(SCRIPT), '--expected-sha', sha,
           '--python-311', str(fixtures['python311']),
           '--python-312', str(fixtures['python312']),
           '--go', str(fixtures['go']), '--out', str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = json.loads(out.read_text()) if out.is_file() else {}
    return proc, output


def edit(folder, fn):
    path = folder / 'manifest.json'
    d = json.loads(path.read_text())
    fn(d)
    path.write_text(json.dumps(d))


def assert_hold(fixtures):
    result, output = invoke(fixtures)
    assert result.returncode != 0, output
    assert output['status'] == 'HOLD'
    assert output['production_eligible'] is False
    assert output['source_authenticity_verified'] is False


def test_three_exact_matching_scopes_are_consistent_not_production_verified(fixtures):
    proc, out = invoke(fixtures)
    assert proc.returncode == 0, proc.stderr
    assert out['status'] == 'EVIDENCE_CONSISTENT'
    assert out['expected_sha'] == SHA
    assert out['scope_count'] == 3
    assert out['source_authenticity_verified'] is False
    assert out['production_eligible'] is False
    assert {x['scope_label'] for x in out['scopes']} == {'python-3.11', 'python-3.12', 'go'}


def test_different_source_sha_is_hold(fixtures):
    edit(fixtures['python312'], lambda d: d.update(expected_sha='b' * 40, actual_sha='b' * 40, post_run_sha='b' * 40))
    assert_hold(fixtures)


def test_missing_manifest_is_hold(fixtures):
    (fixtures['go'] / 'manifest.json').unlink()
    assert_hold(fixtures)


def test_failed_step_is_hold_even_when_manifest_says_pass(fixtures):
    edit(fixtures['go'], lambda d: d['checks'][1].update(return_code=42))
    assert_hold(fixtures)


def test_deleted_step_is_hold(fixtures):
    edit(fixtures['go'], lambda d: d['checks'].pop())
    assert_hold(fixtures)


def test_tampered_log_is_hold(fixtures):
    (fixtures['python311'] / 'python-pytest.log').write_text('tampered\n')
    assert_hold(fixtures)


def test_symlinked_log_is_hold(fixtures):
    p = fixtures['python311'] / 'python-pytest.log'
    link_target = p.with_suffix('.original')
    p.rename(link_target)
    p.symlink_to(link_target)
    assert_hold(fixtures)


def test_duplicate_manifest_json_keys_are_hold(fixtures):
    p = fixtures['go'] / 'manifest.json'
    s = p.read_text().strip()
    p.write_text(s[:-1] + ',"status":"PASS"}\n')
    assert_hold(fixtures)


def test_wrong_python_matrix_version_is_hold(fixtures):
    edit(fixtures['python311'], lambda d: d.update(python_version='3.13'))
    assert_hold(fixtures)


def test_mutated_git_worktree_after_tests_is_hold(fixtures):
    edit(fixtures['python312'], lambda d: d.update(post_run_tree_clean=False))
    assert_hold(fixtures)


def test_wrong_go_command_is_hold(fixtures):
    edit(fixtures['go'], lambda d: d['checks'][0].update(argv=['echo', 'PASS']))
    assert_hold(fixtures)


def test_alias_two_python_artifact_paths_is_hold(fixtures):
    fixtures['python312'] = fixtures['python311']
    assert_hold(fixtures)


def test_boolean_return_code_is_hold(fixtures):
    edit(fixtures['python312'], lambda d: d['checks'][0].update(return_code=False))
    assert_hold(fixtures)


def test_invalid_requested_sha_is_hold(fixtures):
    proc, out = invoke(fixtures, sha='main')
    assert proc.returncode != 0
    assert out['status'] == 'HOLD'


def test_untracked_git_status_is_hold(fixtures):
    edit(fixtures['go'], lambda d: d.update(tracked_tree_clean=False))
    assert_hold(fixtures)


def test_log_path_escape_is_hold(fixtures):
    edit(fixtures['go'], lambda d: d['checks'][0].update(log_path='../outside.log'))
    assert_hold(fixtures)


def test_built_go_binary_contract_is_consistent(fixtures):
    edit(fixtures['go'], lambda d: d['checks'][3].update(argv=[
        d['checks'][2]['argv'][3], 'verify-bundle', '--scenario', '--file',
        '/checkout/benchmarks/scenarios/checkout-latency.json']))
    proc, output = invoke(fixtures)
    assert proc.returncode == 0, proc.stderr
    assert output['status'] == 'EVIDENCE_CONSISTENT'


def test_legacy_go_run_receipt_is_hold(fixtures):
    edit(fixtures['go'], lambda d: d['checks'][3].update(argv=[
        'go', 'run', './cmd/sre-agent', 'verify-bundle', '--scenario', '--file',
        'benchmarks/scenarios/checkout-latency.json']))
    assert_hold(fixtures)


@pytest.mark.parametrize('bad_argv', [
    ['/other/sre-agent', 'verify-bundle', '--scenario', '--file', '/checkout/benchmarks/scenarios/checkout-latency.json'],
    ['/tmp/sre-exact-go/sre-agent', 'verify-bundle', '--scenario', '--file', 'benchmarks/scenarios/checkout-latency.json'],
    ['/tmp/sre-exact-go/sre-agent', 'verify-bundle', '--scenario', '--file', '/checkout/benchmarks/scenarios/other.json'],
])
def test_go_smoke_must_use_built_path_and_checkout_fixture(fixtures, bad_argv):
    edit(fixtures['go'], lambda d: d['checks'][3].update(argv=bad_argv))
    assert_hold(fixtures)


def test_zero_exit_with_error_is_hold(fixtures):
    edit(fixtures['python311'], lambda d: d['checks'][0].update(error='invalid receipt'))
    assert_hold(fixtures)


@pytest.mark.parametrize('fault', ['empty', 'wrong_digest', 'wrong_status', 'float_count', 'duplicate', 'deep', 'oversized'])
def test_rehashed_invalid_go_contract_log_is_hold(fixtures, fault):
    path = fixtures['go'] / 'go-bundle-contract.log'
    raw = path.read_bytes()
    if fault == 'empty':
        raw = b''
    elif fault == 'wrong_digest':
        data = json.loads(raw)
        data['bundle_sha256'] = '0' * 64
        raw = json.dumps(data).encode()
    elif fault == 'wrong_status':
        raw = raw.replace(b'STRUCTURALLY_VALID', b'INVALID')
    elif fault == 'float_count':
        raw = raw.replace(b'"evidence_count": 2', b'"evidence_count": 2.0')
    elif fault == 'duplicate':
        raw = b'{"status":"STRUCTURALLY_VALID",' + raw[1:]
    elif fault == 'deep':
        raw = b'[' * 1500 + b'0' + b']' * 1500
    elif fault == 'oversized':
        raw += b' ' * 4096
    path.write_bytes(raw)
    edit(fixtures['go'], lambda d: d['checks'][3].update(
        log_sha256=hashlib.sha256(raw).hexdigest()))
    assert_hold(fixtures)


@pytest.mark.parametrize('mutation', ['grow', 'shrink', 'same_size'])
def test_ci_reader_rejects_mutation_after_initial_stat(tmp_path, monkeypatch, mutation):
    import importlib.util
    import os

    spec = importlib.util.spec_from_file_location('ci_evidence_reader', SCRIPT)
    checker = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(checker)
    path = tmp_path / 'evidence.log'
    original = b'original evidence\n'
    path.write_bytes(original)
    real_fstat = os.fstat
    calls = 0

    def mutate_after_first_stat(fd):
        nonlocal calls
        info = real_fstat(fd)
        calls += 1
        if calls == 1:
            if mutation == 'grow':
                path.write_bytes(original + b'changed')
            elif mutation == 'shrink':
                path.write_bytes(original[:-1])
            else:
                path.write_bytes(b'X' * len(original))
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        return info

    monkeypatch.setattr(checker.os, 'fstat', mutate_after_first_stat)
    with pytest.raises(ValueError, match='changed during read'):
        checker.read_regular(path, 1024, 'log')
    assert calls >= 2


def test_ci_reader_accepts_unchanged_empty_log(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location('ci_evidence_reader', SCRIPT)
    checker = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(checker)
    path = tmp_path / 'empty.log'
    path.touch()
    # Successful go vet/build commands may legitimately produce no stdout.
    assert checker.read_regular(path, 1024, 'log') == b''
