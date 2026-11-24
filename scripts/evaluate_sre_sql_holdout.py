#!/usr/bin/env python3
"""Pinned, synthetic/disposable read-only SQL scoring; no production DB access."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys

from agentic_aiops.sql_holdout import evaluate_sql_case


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _pinned(path, digest, identities):
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid SHA256 pin")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("secure read unsupported")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        ident = (s.st_dev, s.st_ino)
        if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= 128 * 1024 or ident in identities:
            raise ValueError("invalid artifact identity or size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(128 * 1024 + 1)
        if not raw or len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("artifact pin mismatch")
        identities.add(ident)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("case", "case-sha256", "prediction", "prediction-sha256"):
        p.add_argument("--" + arg, required=True)
    a = p.parse_args()
    try:
        seen = set()
        case = _pinned(a.case, a.case_sha256, seen)
        pred = _pinned(a.prediction, a.prediction_sha256, seen)
        if type(pred) is not dict or set(pred) != {"case_id", "sql"} or pred["case_id"] != case["case_id"]:
            raise ValueError("case identity mismatch")
        result = evaluate_sql_case(case, pred["sql"])
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        print("HOLD: invalid or unauthenticated SQL holdout input", file=sys.stderr)
        return 3
    print(json.dumps({**result, "case_sha256": a.case_sha256,
                      "prediction_sha256": a.prediction_sha256}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
