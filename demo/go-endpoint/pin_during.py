#!/usr/bin/env python3
"""Pin independent test-admin EndpointSlice replay to the observer's exact LIST version.

Only a disposable kind LAB tool. It does not authenticate Kubernetes source
identity, grant writes, or establish root cause in arbitrary production incidents.
"""
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

MAX_RESPONSE_BYTES = 2 << 20
ENDPOINT_LIST_PATH = (
    "/apis/discovery.k8s.io/v1/namespaces/golden-demo/endpointslices"
)
ENDPOINT_LIST_QUERY = {
    "labelSelector": "kubernetes.io/service-name=checkout-api",
    "limit": "129",
}
MAX_RESOURCE_VERSION_BYTES = 256
MAX_JSON_DEPTH = 64


@dataclass(frozen=True)
class NumberToken:
    """Preserve JSON number spelling and distinguish it from bool/string."""
    lexeme: str


def reject_nonfinite(token):
    raise ValueError(f"invalid JSON number constant {token}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def validate_unicode(value):
    """Reject unpaired surrogates and excessive nesting in decoded JSON evidence."""
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("EndpointSlice JSON nesting exceeds the safe depth limit")
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("invalid Unicode scalar value in EndpointSlice JSON") from exc
        elif isinstance(current, dict):
            for key, item in current.items():
                pending.append((key, depth + 1))
                pending.append((item, depth + 1))
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def read_bounded_regular_file(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("safe no-follow, nonblocking file access is unavailable")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("EndpointSlice evidence must be a regular file")
        if info.st_size > MAX_RESPONSE_BYTES:
            raise ValueError("EndpointSlice list exceeds bounded response size")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_RESPONSE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("empty or oversized EndpointSlice response")
    return raw


def read_list(path):
    source = Path(path)
    raw = read_bounded_regular_file(source)
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_object,
            parse_int=NumberToken, parse_float=NumberToken,
            parse_constant=reject_nonfinite,
        )
    except RecursionError as exc:
        raise ValueError("EndpointSlice JSON nesting exceeds the parser limit") from exc
    validate_unicode(data)
    if not isinstance(data, dict) or data.get("kind") != "EndpointSliceList":
        raise ValueError("expected a Kubernetes EndpointSliceList")
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("missing EndpointSlice list metadata")
    version = metadata.get("resourceVersion")
    if (
        not isinstance(version, str)
        or not version
        or version == "0"
        or len(version.encode("utf-8")) > MAX_RESOURCE_VERSION_BYTES
    ):
        raise ValueError("invalid/oversized opaque resourceVersion; cannot pin snapshot")
    if "continue" in metadata and metadata["continue"] != "":
        raise ValueError("paginated list: cannot claim complete exact snapshot")
    if "remainingItemCount" in metadata:
        remaining = metadata["remainingItemCount"]
        if remaining != NumberToken("0"):
            raise ValueError("invalid or incomplete remainingItemCount")
    items = data.get("items")
    if not isinstance(items, list) or len(items) > 128:
        raise ValueError("incomplete/oversized EndpointSlice membership")
    return data, version


def main(argv):
    if len(argv) == 1:
        _, version = read_list(argv[0])
        query = urlencode({
            **ENDPOINT_LIST_QUERY,
            "resourceVersion": version,
            "resourceVersionMatch": "Exact",
        })
        print(f"{ENDPOINT_LIST_PATH}?{query}")
        return 0
    if len(argv) == 3 and argv[0] == "--verify":
        observer, observed_version = read_list(argv[1])
        admin, admin_version = read_list(argv[2])
        if admin_version != observed_version or admin != observer:
            raise ValueError("test-admin exact-RV source disagrees with observer snapshot")
        print(f"PASS: independently re-fetched EndpointSlice list at exact RV {observed_version}")
        return 0
    raise ValueError("usage: pin_during.py OBSERVER_LIST | --verify OBSERVER_LIST ADMIN_LIST")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"UNKNOWN: cannot pin/reconcile EndpointSlice source: {exc}", file=sys.stderr)
        sys.exit(3)
