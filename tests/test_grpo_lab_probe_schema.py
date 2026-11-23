"""Adversarial G2i probe schema checks before importing a GRPO candidate.

G2i's Kubernetes Service IP and DNS answer are text addresses, never
integer IPv4Address constructor inputs or heterogeneous JSON arrays.
"""
import json

import pytest

from agentic_aiops.grpo_lab_intake import _check_probe


def healthy():
    return {
        "schema_version": "sre.dns-probe/v1",
        "host": "checkout-api.golden-demo.svc.cluster.local",
        "service_ip": "10.96.0.100",
        "dns_addresses": ["10.96.0.100"],
        "dns_ok": True,
        "dns_error": "",
        "direct_http_attempts": [200, 200, 200],
        "name_http_status": 200,
        "direct_http_status": 200,
    }


def test_real_kubernetes_service_dns_address_schema_accepted():
    p = healthy()
    assert _check_probe(json.dumps(p).encode("utf-8"), "before") == p


@pytest.mark.parametrize("bad_ip", [1, 1681915905, True, None, ["10.96.0.100"]])
def test_rejects_non_string_service_ip_even_when_dns_list_forged_to_match(bad_ip):
    probe = healthy()
    probe["service_ip"] = bad_ip
    probe["dns_addresses"] = [bad_ip]
    with pytest.raises(ValueError, match="service_ip|DNS"):
        _check_probe(json.dumps(probe).encode("utf-8"), "before")


@pytest.mark.parametrize("bad_answers", [
    ["10.96.0.100", 1681915905],
    ["10.96.0.100", None],
    ["10.96.0.100", False],
])
def test_rejects_heterogeneous_dns_answers_even_with_correct_service_ip(bad_answers):
    probe = healthy()
    probe["dns_addresses"] = bad_answers
    with pytest.raises(ValueError, match="DNS"):
        _check_probe(json.dumps(probe).encode("utf-8"), "before")
