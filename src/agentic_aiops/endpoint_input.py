"""Bound local Endpoint evidence reads to regular, final-component no-follow files."""
import os
from pathlib import Path
import stat


def read_bounded_input(path: str | Path, limit: int) -> bytes:
    """Read exact bytes from the opened inode; reject FIFOs and symlinks.

    The operator must select a trusted parent directory. No source provenance
    or immutable custody is established by this local admission check.
    """
    if type(limit) is not int or limit <= 0:
        raise ValueError("invalid input limit")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise OSError("safe no-follow, nonblocking file access unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular input file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if not raw or len(raw) > limit:
        raise ValueError("empty or oversized input")
    return raw
