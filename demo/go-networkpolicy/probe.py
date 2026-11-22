"""Bounded real Pod DNS + HTTP dataplane probe for disposable kind.

This Pod never carries Kubernetes credentials and never modifies cluster state.
Every HTTP attempt is recorded. A policy denial must NOT be inferred solely
from an existing Kubernetes NetworkPolicy object.
"""
import json
import os
import socket
import urllib.error
import urllib.request
import time

HOST = os.environ["SERVICE_HOST"]
IP = os.environ["SERVICE_IP"]
PORT = 8080
PHASE = os.environ["PROBE_PHASE"]
with open("/etc/resolv.conf", "r", encoding="utf-8") as stream:
    RESOLVER = stream.read()

dns_addresses = []
dns_error = ""
try:
    dns_addresses = sorted(set(result[4][0] for result in
      socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)))
except (socket.gaierror, OSError) as exc:
    dns_error = str(exc)
dns_ok = len(dns_addresses) > 0 and not dns_error

def http_status(target):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://{target}:{PORT}/healthz", timeout=2) as resp:
            return int(resp.status), ""
    except urllib.error.HTTPError as exc:
        return int(exc.code), str(exc)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, str(exc)[:256]

# Different request paths must be tested, not inferred from DNS results.
name_status, name_error = http_status(HOST) if dns_ok else (0, "DNS failed")
direct_attempts = []
direct_errors = []
for attempt in range(3):
    code, reason = http_status(IP)
    direct_attempts.append(code)
    direct_errors.append(reason)
    time.sleep(0.2)

probe = {
    "schema_version": "sre.dns-probe/v1",
    "host": HOST,
    "service_ip": IP,
    "resolver": RESOLVER,
    "dns_ok": dns_ok,
    "dns_addresses": dns_addresses,
    "dns_error": dns_error,
    "name_http_status": name_status,
    "direct_http_status": direct_attempts[-1],
    "direct_http_attempts": direct_attempts,
    "direct_http_errors": direct_errors,
}
print(json.dumps(probe, sort_keys=True, separators=(",", ":")), flush=True)
