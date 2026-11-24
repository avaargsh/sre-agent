#!/usr/bin/env python3
"""Pin independent test-admin EndpointSlice replay to the observer's exact LIST version.

Only a disposable kind LAB tool. It does not authenticate Kubernetes source
identity, grant writes, or establish root cause in arbitrary production incidents.
"""
import json
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
    """Reject unpaired UTF-16 surrogates anywhere in decoded JSON evidence."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("invalid Unicode scalar value in EndpointSlice JSON") from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_unicode(key)
            validate_unicode(item)
    elif isinstance(value, list):
        for item in value:
            validate_unicode(item)


def read_list(path):
    source = Path(path)
    if source.stat().st_size > MAX_RESPONSE_BYTES:
        raise ValueError("EndpointSlice list exceeds bounded response size")
    raw = source.read_bytes()
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("empty or oversized EndpointSlice response")
    data = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique_object,
        parse_int=NumberToken, parse_float=NumberToken,
        parse_constant=reject_nonfinite,
    )
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
