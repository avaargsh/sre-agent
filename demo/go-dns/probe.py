"""A tiny bounded, one-shot client DNS probe executed inside a disposable Pod.

Never needs Kubernetes credentials. It emits exactly one JSON object on stdout.
DNS evidence and direct-IP reachability are intentionally separate signals.
"""
import json
import os
import socket
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
    # Ignore ambient proxy settings, so curl/HTTP success cannot be a
    # side-effect of routing through a proxy instead of the Service IP.
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://{host}:{PORT}/healthz", timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0


name_http = http_status(HOST) if dns_ok else 0
direct_http = http_status(IP)
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
}, sort_keys=True, separators=(",", ":")), flush=True)
