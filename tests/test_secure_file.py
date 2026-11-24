import os

import pytest

from agentic_aiops.secure_file import read_pinned_regular


def test_reads_exact_regular_file_bytes_and_returns_inode_identity(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(b'{"safe":true}')
    raw, identity = read_pinned_regular(source, limit=1024, label="source")
    assert raw == b'{"safe":true}'
    assert identity == (source.stat().st_dev, source.stat().st_ino)


def test_rejects_final_component_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"content")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        read_pinned_regular(alias, limit=1024, label="input")


def test_rejects_symlinked_parent_component(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "input").write_bytes(b"content")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|component"):
        read_pinned_regular(alias / "input", limit=1024, label="input")


def test_rejects_parent_traversal_even_when_path_resolves_inside_root(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    target = child / "input"
    target.write_bytes(b"content")
    traversed = child / ".." / "child" / "input"
    with pytest.raises(ValueError, match="traversal"):
        read_pinned_regular(traversed, limit=1024, label="input")


def test_rejects_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "input.fifo"
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular"):
        read_pinned_regular(fifo, limit=1024, label="input")


def test_rejects_directory_and_oversized_or_empty_file(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * 1025)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    for path in (directory, oversized, empty):
        with pytest.raises(ValueError):
            read_pinned_regular(path, limit=1024, label="input")


def test_hardlinks_report_same_inode_identity(tmp_path):
    source = tmp_path / "source"
    alias = tmp_path / "alias"
    source.write_bytes(b"same bytes")
    os.link(source, alias)
    _, source_identity = read_pinned_regular(source, limit=1024, label="source")
    _, alias_identity = read_pinned_regular(alias, limit=1024, label="alias")
    assert source_identity == alias_identity

def test_duplicate_inode_is_rejected_before_a_second_read(tmp_path):
    source = tmp_path / "source"
    alias = tmp_path / "alias"
    source.write_bytes(b"same bytes")
    os.link(source, alias)
    identities = set()
    raw, identity = read_pinned_regular(
        source, limit=1024, label="source", identities=identities,
    )
    assert raw == b"same bytes"
    assert identity in identities
    with pytest.raises(ValueError, match="distinct|duplicate"):
        read_pinned_regular(
            alias, limit=1024, label="alias", identities=identities,
        )


def test_create_only_pair_writes_into_component_pinned_directories(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    publish_create_only_pair(output, b'{"episode_id":"a"}\n',
                             manifest, b'{"complete":true}\n')
    assert output.read_bytes() == b'{"episode_id":"a"}\n'
    assert manifest.read_bytes() == b'{"complete":true}\n'


@pytest.mark.parametrize("target", ["output", "manifest"])
def test_create_only_pair_rejects_symlinked_parent_before_writing(tmp_path, target):
    from agentic_aiops.secure_file import publish_create_only_pair

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    output = alias / "predictions.jsonl" if target == "output" else real / "predictions.jsonl"
    manifest = alias / "capture.json" if target == "manifest" else real / "capture.json"

    with pytest.raises(ValueError, match="symlink|component"):
        publish_create_only_pair(output, b"prediction", manifest, b"manifest")
    assert not (real / "predictions.jsonl").exists()
    assert not (real / "capture.json").exists()


def test_create_only_pair_rejects_parent_traversal(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "child" / ".." / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    (tmp_path / "child").mkdir()
    with pytest.raises(ValueError, match="traversal"):
        publish_create_only_pair(output, b"prediction", manifest, b"manifest")
    assert not (tmp_path / "predictions.jsonl").exists()
    assert not manifest.exists()


def test_create_only_pair_never_overwrites_existing_manifest_or_output(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    manifest.write_bytes(b"previous-manifest")
    with pytest.raises(FileExistsError):
        publish_create_only_pair(output, b"new-predictions", manifest, b"new-manifest")
    # The first link can exist as an orphan, but it is never a complete capture.
    assert output.read_bytes() == b"new-predictions"
    assert manifest.read_bytes() == b"previous-manifest"
    assert not list(tmp_path.glob(".sre-capture-*.stage"))


def test_create_only_pair_rejects_same_final_path(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "same.json"
    manifest = tmp_path / "same.json"
    with pytest.raises(ValueError, match="distinct"):
        publish_create_only_pair(output, b"one", manifest, b"two")
    assert not output.exists()


def test_create_only_pair_files_are_private_mode(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    publish_create_only_pair(output, b"prediction", manifest, b"manifest")
    assert output.stat().st_mode & 0o777 == 0o600
    assert manifest.stat().st_mode & 0o777 == 0o600


def test_create_only_pair_does_not_overwrite_existing_output(tmp_path):
    from agentic_aiops.secure_file import publish_create_only_pair

    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    output.write_bytes(b"previous-predictions")
    with pytest.raises(FileExistsError):
        publish_create_only_pair(output, b"new-predictions", manifest, b"new-manifest")
    assert output.read_bytes() == b"previous-predictions"
    assert not manifest.exists()
    assert not list(tmp_path.glob(".sre-capture-*.stage"))


@pytest.mark.parametrize("target", ["output", "manifest"])
def test_create_only_pair_never_follows_existing_final_symlink(tmp_path, target):
    from agentic_aiops.secure_file import publish_create_only_pair

    victim = tmp_path / "victim"
    victim.write_bytes(b"must-not-change")
    output = tmp_path / "predictions.jsonl"
    manifest = tmp_path / "capture.json"
    selected = output if target == "output" else manifest
    selected.symlink_to(victim)

    with pytest.raises(FileExistsError):
        publish_create_only_pair(output, b"new-predictions", manifest, b"new-manifest")

    assert victim.read_bytes() == b"must-not-change"
    assert selected.is_symlink()
    if target == "output":
        assert not manifest.exists()
    else:
        # A prediction-only orphan is not a complete capture.
        assert output.read_bytes() == b"new-predictions"
