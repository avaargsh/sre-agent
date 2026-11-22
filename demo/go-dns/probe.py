"""A tiny bounded, one-shot client DNS probe executed inside a disposable Pod.

Never needs Kubernetes credentials. It emits exactly one JSON object on stdout.
DNS evidence and direct-IP reachability are intentionally separate signals.
"""
import json
import os
import socket
import time
import urllib.error
import urllib.request

HOST = os.environ["SERVICE_HOST"]
IP = os.environ["SERVICE_IP"]
PORT = 8080
with open("/etc/resolv.conf", "r", encoding="utf-8") as stream:
    resolver = stream.read()

addresses = []
dns_error = ""
try:
    for address in socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM):
        addresses.append(address[4][0])
    addresses = sorted(set(addresses))
except (socket.gaierror, OSError) as exc:
    dns_error = str(exc)

dns_ok = bool(addresses) and not dns_error


def http_status(host):
    # No ambient HTTP_PROXY. Preserve the actual failure reason for diagnosis.
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://{host}:{PORT}/healthz", timeout=5) as response:
            return response.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, str(exc)


name_http, name_http_error = http_status(HOST) if dns_ok else (0, "")
# A just-started Pod can briefly have incomplete dataplane routing even when
# a previously started control Pod already succeeds. Keep every attempt and
# require a genuine successful direct-IP request before claiming DNS-only.
direct_attempts = []
direct_errors = []
for attempt in range(8):
    status, reason = http_status(IP)
    direct_attempts.append(status)
    direct_errors.append(reason[:256])
    if status == 200:
        break
    time.sleep(1)
direct_http = direct_attempts[-1]
print(json.dumps({
    "schema_version": "sre.dns-probe/v1",
    "host": HOST,
    "service_ip": IP,
    "resolver": resolver,
    "dns_ok": dns_ok,
    "dns_addresses": addresses,
    "dns_error": dns_error,
    "name_http_status": name_http,
    "direct_http_status": direct_http,
    "direct_http_attempts": direct_attempts,
    "direct_http_errors": direct_errors,
}, sort_keys=True, separators=(",", ":")), flush=True)
