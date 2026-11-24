"""Component-safe bounded reads of externally pinned regular files."""

from __future__ import annotations

import errno
import os
import stat
import uuid
from pathlib import Path


def _secure_open_supported() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_NONBLOCK")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "supports_fd")
        and os.open in os.supports_dir_fd
    )


def _open_parent(path: str | Path) -> tuple[int, str]:
    """Walk every parent directory without following symbolic links."""
    if not _secure_open_supported():
        raise ValueError("component-safe no-follow file opening unavailable")
    raw_path = os.fsdecode(os.fspath(path))
    if not raw_path or chr(0) in raw_path:
        raise ValueError("invalid pinned file path")
    absolute = os.path.isabs(raw_path)
    parts = [part for part in raw_path.split(os.sep) if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("pinned file path contains parent traversal")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(os.sep if absolute else ".", directory_flags)
    try:
        for component in parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(
                        f"symlink or non-directory path component rejected: {component}"
                    ) from exc
                raise
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, parts[-1]
    except BaseException:
        os.close(directory_fd)
        raise


def read_pinned_regular(
    path: str | Path, *, limit: int, label: str,
    identities: set[tuple[int, int]] | None = None,
) -> tuple[bytes, tuple[int, int]]:
    """Read bounded bytes and return the opened inode identity.

    The path is walked component by component through pinned directory file
    descriptors. The final inode is opened with O_NOFOLLOW|O_NONBLOCK, checked
    with fstat, and read through that same descriptor. Hash the returned bytes;
    never reopen the pathname to verify or parse it.
    """
    if type(limit) is not int or limit <= 0:
        raise ValueError("invalid pinned file byte limit")
    if type(label) is not str or not label:
        raise ValueError("invalid pinned file label")

    parent_fd, name = _open_parent(path)
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"{label} symlink rejected") from exc
            raise
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or not 0 < info.st_size <= limit
            ):
                raise ValueError(f"{label} must be a bounded regular file")
            identity = (info.st_dev, info.st_ino)
            if identities is not None and identity in identities:
                raise ValueError("pinned input inodes must be distinct")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw = stream.read(limit + 1)
            if not raw or len(raw) > limit:
                raise ValueError(f"{label} outside bounded byte budget")
            if identities is not None:
                identities.add(identity)
            return raw, identity
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        os.close(parent_fd)


def _write_create_only_at(directory_fd: int, name: str, payload: bytes) -> int:
    """Create and fsync one private final file without following or replacing names."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing capture")
            view = view[written:]
        os.fsync(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def publish_create_only_pair(
    output: str | Path, output_bytes: bytes,
    manifest: str | Path, manifest_bytes: bytes,
) -> None:
    """Publish a create-only prediction/manifest pair through pinned parents.

    Parent symlinks and traversal are rejected. Each final file is opened with
    O_CREAT|O_EXCL|O_NOFOLLOW and mode 0600, then written and fsynced through
    that same descriptor. The manifest is created last. If its creation fails,
    the prediction may remain as an orphan; consumers must require both
    independently pinned files before treating the capture as complete.
    """
    if type(output_bytes) is not bytes or type(manifest_bytes) is not bytes:
        raise ValueError("capture payloads must be bytes")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
        or not hasattr(os, "supports_dir_fd")
        or os.open not in os.supports_dir_fd
    ):
        raise ValueError("descriptor-relative create-only publication unavailable")

    output_fd, output_name = _open_parent(output)
    manifest_fd = -1
    output_file_fd = -1
    manifest_file_fd = -1
    try:
        manifest_fd, manifest_name = _open_parent(manifest)
        output_info = os.fstat(output_fd)
        manifest_info = os.fstat(manifest_fd)
        if (
            (output_info.st_dev, output_info.st_ino, output_name)
            == (manifest_info.st_dev, manifest_info.st_ino, manifest_name)
        ):
            raise ValueError("output and manifest paths must be distinct")

        output_file_fd = _write_create_only_at(output_fd, output_name, output_bytes)
        os.fsync(output_fd)
        # The manifest is the last-created commit marker for this capture.
        manifest_file_fd = _write_create_only_at(
            manifest_fd, manifest_name, manifest_bytes,
        )
        os.fsync(manifest_fd)
    finally:
        if manifest_file_fd >= 0:
            os.close(manifest_file_fd)
        if output_file_fd >= 0:
            os.close(output_file_fd)
        if manifest_fd >= 0:
            os.close(manifest_fd)
        os.close(output_fd)
