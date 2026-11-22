"""Strictly require a completely healthy pre-injection dataplane baseline.

Used only to warm up a disposable Calico/kind cluster BEFORE any fault is
injected. This NEVER relaxes the independent offline G2i Oracle or the
during/after tests. Each rejected attempt must be preserved as original log.
"""
import json
import pathlib
import sys


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def healthy(probe, service_ip):
    if not isinstance(probe, dict) or not isinstance(service_ip, str):
        return False
    return (
        probe.get("schema_version") == "sre.dns-probe/v1"
        and probe.get("host") == "checkout-api.golden-demo.svc.cluster.local"
        and probe.get("service_ip") == service_ip
        and probe.get("dns_ok") is True
        and probe.get("dns_error") == ""
        and isinstance(probe.get("dns_addresses"), list)
        and service_ip in probe["dns_addresses"]
        and probe.get("name_http_status") == 200
        and probe.get("direct_http_status") == 200
        and probe.get("direct_http_attempts") == [200, 200, 200]
        and probe.get("direct_http_errors") == ["", "", ""]
    )


def main():
    if len(sys.argv) != 3:
        print("UNKNOWN: expected probe JSON and exact Service IP", file=sys.stderr)
        return 3
    try:
        raw = pathlib.Path(sys.argv[1]).read_bytes()
        if not raw or len(raw) > 65536:
            raise ValueError("probe exceeds bounded source budget")
        probe = json.loads(raw, object_pairs_hook=unique_pairs)
    except (OSError, ValueError, UnicodeError):
        print("UNKNOWN: missing, ambiguous or malformed baseline probe", file=sys.stderr)
        return 3
    if not healthy(probe, sys.argv[2]):
        print("UNKNOWN: DNS and every HTTP path are not all healthy", file=sys.stderr)
        return 3
    print("PASS: fully healthy DNS, named HTTP and three direct-IP HTTP 200 attempts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
