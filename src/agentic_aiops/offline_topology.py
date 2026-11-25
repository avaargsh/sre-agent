"""Build a structural topology from local Kubernetes snapshots, not live discovery."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MAX_SNAPSHOT_BYTES = 8 << 20


def _object(value):
    if not isinstance(value, dict):
        raise ValueError("expected object")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected nonempty identifier")
    return value


def _string_map(value):
    value = _object(value)
    if not all(isinstance(k, str) and k and isinstance(v, str) for k, v in value.items()):
        raise ValueError("invalid label map")
    return value


def _identity(item, kind, namespace=None, *, typed_list=False):
    item = _object(item)
    if item.get("kind", kind if typed_list else None) != kind:
        raise ValueError("unexpected object kind")
    meta = _object(item.get("metadata"))
    ns = _text(meta.get("namespace"))
    if namespace is not None and ns != namespace:
        raise ValueError("namespace mismatch")
    return {"entity_id": _text(meta.get("uid")), "kind": kind,
            "name": _text(meta.get("name")), "attributes": {"namespace": ns}}


def _controller(meta):
    refs = meta.get("ownerReferences", [])
    if not isinstance(refs, list):
        raise ValueError("invalid owner references")
    controllers = []
    for ref in refs:
        ref = _object(ref)
        if "controller" in ref and type(ref["controller"]) is not bool:
            raise ValueError("invalid controller flag")
        if ref.get("controller") is True:
            controllers.append((_text(ref.get("kind")), _text(ref.get("name")),
                                _text(ref.get("uid")), ref.get("apiVersion")))
    if len(controllers) > 1:
        raise ValueError("multiple controllers")
    return controllers[0] if controllers else None


def _optional_count(fields, key):
    if key not in fields:
        return None
    value = fields[key]
    if type(value) is not int or value < 0:
        raise ValueError("invalid deployment count or generation")
    return value


def _deployment_observation(item, uid):
    spec = _object(item.get("spec", {}))
    status = _object(item.get("status", {}))
    generation = _optional_count(item["metadata"], "generation")
    observed = _optional_count(status, "observedGeneration")
    if generation is None or observed is None:
        generation_status = "unknown"
    elif observed < generation:
        generation_status = "stale"
    elif observed > generation:
        generation_status = "inconsistent"
    else:
        generation_status = "matches"
    return {
        "entity_id": uid,
        "desired_replicas": _optional_count(spec, "replicas"),
        "replicas": _optional_count(status, "replicas"),
        "ready_replicas": _optional_count(status, "readyReplicas"),
        "available_replicas": _optional_count(status, "availableReplicas"),
        "updated_replicas": _optional_count(status, "updatedReplicas"),
        "generation": generation,
        "observed_generation": observed,
        "generation_status": generation_status,
    }


def build_topology(snapshot: dict) -> dict:
    """Resolve selector matches and exact owner identities in supplied records."""
    snapshot = _object(snapshot)
    service = _object(snapshot.get("service"))
    root = _identity(service, "Service")
    namespace = root["attributes"]["namespace"]
    selector = _string_map(_object(service.get("spec")).get("selector", {}))
    inventory = {root["entity_id"]: root}
    names = {("Service", root["name"])}
    controllers = {}
    pod_labels = {}
    deployment_records = {}
    for field, kind in (("pods", "Pod"), ("replica_sets", "ReplicaSet"), ("deployments", "Deployment")):
        listing = _object(snapshot.get(field))
        list_kind = listing.get("kind")
        if list_kind not in (kind + "List", "List") or _object(listing.get("metadata", {})).get("continue", "") != "":
            raise ValueError("invalid or paginated inventory")
        items = listing.get("items")
        if not isinstance(items, list):
            raise ValueError("invalid inventory items")
        for item in items:
            entity = _identity(item, kind, namespace, typed_list=list_kind == kind + "List")
            uid = entity["entity_id"]
            name_key = (kind, entity["name"])
            if uid in inventory or name_key in names:
                raise ValueError("duplicate object identity")
            inventory[uid] = entity
            names.add(name_key)
            if kind == "Deployment":
                deployment_records[uid] = item
            else:
                controllers[uid] = _controller(item["metadata"])
            if kind == "Pod":
                pod_labels[uid] = _string_map(item["metadata"].get("labels", {}))

    included = {root["entity_id"]: root}
    edges = set()
    unresolved = set()

    def follow(uid, expected_kind):
        ref = controllers[uid]
        if ref is None:
            unresolved.add((uid, "controller_absent"))
            return None
        kind, name, owner_uid, api_version = ref
        candidate = inventory.get(owner_uid)
        if (kind != expected_kind or api_version != "apps/v1" or candidate is None
                or candidate["kind"] != kind or candidate["name"] != name):
            unresolved.add((uid, "controller_not_resolved"))
            return None
        included[owner_uid] = candidate
        edges.add((uid, owner_uid, "controller_reference"))
        return owner_uid

    if not selector:
        unresolved.add((root["entity_id"], "selector_absent"))
    else:
        for uid, labels in pod_labels.items():
            if all(key in labels and labels[key] == value for key, value in selector.items()):
                included[uid] = inventory[uid]
                edges.add((root["entity_id"], uid, "selector_matches"))
                rs_uid = follow(uid, "ReplicaSet")
                if rs_uid is not None:
                    follow(rs_uid, "Deployment")
        if len(included) == 1:
            unresolved.add((root["entity_id"], "no_selector_matches"))
    return {
        "schema_version": "offline-service-topology/v1",
        "entities": [included[uid] for uid in sorted(included)],
        "edges": [{"source": src, "target": dst, "relation": rel} for src, dst, rel in sorted(edges)],
        "unresolved": [{"entity_id": uid, "reason": reason} for uid, reason in sorted(unresolved)],
        "deployment_observations": [
            _deployment_observation(deployment_records[uid], uid)
            for uid in sorted(included) if uid in deployment_records
        ],
        "source_authenticated": False,
        "independently_verified": False,
        "execution_authorized": False,
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_topology_snapshot(path: str | Path) -> dict:
    """Read one bounded local snapshot and bind the graph to its exact bytes."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("oversized snapshot")
    result = build_topology(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object))
    result["snapshot_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="operator-selected local JSON file")
    args = parser.parse_args(argv)
    try:
        rendered = json.dumps(load_topology_snapshot(args.snapshot), indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, RecursionError):
        parser.error("invalid topology snapshot")
    print(rendered)


if __name__ == "__main__":
    main()
