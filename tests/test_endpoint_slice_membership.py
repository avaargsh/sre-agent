import base64
import hashlib
import json

import pytest

from agentic_aiops.endpoint_report import summarize_endpoint_capture
from test_endpoint_report_cli import capture

# Exact HTTP response bodies from cmd/sre-agent/service_endpoints_cli_test.go.
SERVICE = b'{"metadata":{"namespace":"demo","name":"checkout-api","uid":"service-uid-1","resourceVersion":"19"},"spec":{"selector":{"app":"checkout-api"},"ports":[{"port":8080,"targetPort":8080}]}}'
SLICES = b'{"kind":"EndpointSliceList","metadata":{"resourceVersion":"25","continue":""},"items":[{"metadata":{"uid":"slice-uid-1","name":"checkout-api-abc","namespace":"demo","labels":{"kubernetes.io/service-name":"checkout-api"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.10"],"conditions":{"ready":true}}]}]}'


def archive(tmp_path, service, slices):
    data = capture()
    data["report"].update(classification="READY_ENDPOINTS_OBSERVED", ready_endpoints=1)
    for field, raw in (("service_before", service), ("service_after", service), ("endpoint_slices", slices)):
        data[field + "_raw"] = base64.b64encode(raw).decode("ascii")
        data["report"][field + "_sha256"] = hashlib.sha256(raw).hexdigest()
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_native_go_fixture_without_service_kind(tmp_path):
    result = summarize_endpoint_capture(archive(tmp_path, SERVICE, SLICES))
    assert result["source_service_identity_matches_report"] is True
    assert result["slice_membership"] == {"slice_count": 1, "service_owner_uid_matches": 0, "label_only": 1}
    assert result["independently_verified"] is False


def test_native_controller_owner_binding(tmp_path):
    listing = json.loads(SLICES)
    meta = listing["items"][0]["metadata"]
    meta["labels"]["endpointslice.kubernetes.io/managed-by"] = "endpointslice-controller.k8s.io"
    meta["ownerReferences"] = [{"apiVersion": "v1", "kind": "Service", "name": "checkout-api", "uid": "service-uid-1"}]
    service = json.loads(SERVICE)
    service["kind"] = "Service"
    result = summarize_endpoint_capture(archive(tmp_path, json.dumps(service).encode(), json.dumps(listing).encode()))
    assert result["slice_membership"] == {"slice_count": 1, "service_owner_uid_matches": 1, "label_only": 0}
    assert result["source_authenticated"] is False


@pytest.mark.parametrize("fault", ["namespace", "label", "uid", "name", "duplicate_uid", "duplicate_name", "owner_uid", "owner_version", "owner_name", "duplicate_owner", "missing_controller_owner", "owner_array", "pagination", "remaining", "overflow"])
def test_slice_membership_rejects_malformed_or_off_scope_inventory(tmp_path, fault):
    listing = json.loads(SLICES)
    item = listing["items"][0]
    meta = item["metadata"]
    owner = {"apiVersion": "v1", "kind": "Service", "name": "checkout-api", "uid": "service-uid-1"}
    if fault == "namespace":
        meta["namespace"] = "other"
    elif fault == "label":
        meta["labels"]["kubernetes.io/service-name"] = "other"
    elif fault in ("uid", "name"):
        meta[fault] = ""
    elif fault in ("duplicate_uid", "duplicate_name"):
        other = json.loads(json.dumps(item))
        other["metadata"]["name" if fault == "duplicate_uid" else "uid"] = "different"
        listing["items"].append(other)
    elif fault in ("owner_uid", "owner_version", "owner_name"):
        owner[{"owner_uid": "uid", "owner_version": "apiVersion", "owner_name": "name"}[fault]] = "different"
        meta["ownerReferences"] = [owner]
    elif fault == "duplicate_owner":
        meta["ownerReferences"] = [owner, owner]
    elif fault == "missing_controller_owner":
        meta["labels"]["endpointslice.kubernetes.io/managed-by"] = "endpointslice-controller.k8s.io"
    elif fault == "owner_array":
        meta["ownerReferences"] = {}
    elif fault == "pagination":
        listing["metadata"]["continue"] = "next"
    elif fault == "remaining":
        listing["metadata"]["remainingItemCount"] = 1
    else:
        listing["items"] *= 129
    service = json.loads(SERVICE)
    service["kind"] = "Service"
    with pytest.raises(ValueError):
        summarize_endpoint_capture(archive(tmp_path, json.dumps(service).encode(), json.dumps(listing).encode()))
