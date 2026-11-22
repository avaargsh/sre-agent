#!/usr/bin/env bash
# Runs only inside an ephemeral kind cluster. ADMIN writes are deliberate fault
# injection; the read-only SRE observer has GET Service and nothing else.
set -euo pipefail

kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-oracle/reader-role.yaml
kubectl -n golden-demo rollout status deployment/checkout-api --timeout=180s
kubectl -n golden-demo scale deployment/load-generator --replicas=1
kubectl -n golden-demo rollout status deployment/load-generator --timeout=180s

ROOT=/tmp/go-oracle-proof
mkdir -p "$ROOT/control" "$ROOT/misroute" "$ROOT/selector"
chmod 0700 "$ROOT"
go build -o /tmp/sre-agent-oracle ./cmd/sre-agent

SERVER="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/go-oracle-ca.crt
chmod 0600 /tmp/go-oracle-ca.crt
TOKEN="$(kubectl -n golden-demo create token sre-oracle-observer --duration=10m)"
OBS_CONFIG=/tmp/go-oracle-observer.kubeconfig
kubectl config --kubeconfig="$OBS_CONFIG" set-cluster read-only-kind --server="$SERVER" --certificate-authority=/tmp/go-oracle-ca.crt --embed-certs=true >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" set-credentials observer --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" set-context observer --cluster=read-only-kind --user=observer >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" use-context observer >/dev/null
chmod 0600 "$OBS_CONFIG"

# This observer config has no administrator client certificate or key.
test "$(kubectl --kubeconfig="$OBS_CONFIG" auth can-i get services/checkout-api -n golden-demo)" = yes
test "$(kubectl --kubeconfig="$OBS_CONFIG" auth can-i patch services/checkout-api -n golden-demo)" = no
test "$(kubectl --kubeconfig="$OBS_CONFIG" auth can-i get secrets -n golden-demo)" = no
test "$(kubectl --kubeconfig="$OBS_CONFIG" auth can-i list pods -n golden-demo)" = no

restore() {
 kubectl -n golden-demo patch svc checkout-api --type=merge -p '{"spec":{"ports":[{"port":8080,"targetPort":8080}],"selector":{"app":"checkout-api"}}}' >/dev/null 2>&1 || true
 rm -f "$OBS_CONFIG" /tmp/go-oracle-ca.crt
}
trap restore EXIT

probe() {
 local dir="$1" phase="$2" code i
 : > "$dir/$phase-probes.txt"
 for i in 1 2 3; do
  # Independent admin-controlled HTTP check from a pod in the same kind
  # namespace. HTTP 000 means connection failed. Preserve every observed code.
  code="$(kubectl -n golden-demo exec deploy/load-generator -c load -- \
    curl -sS --connect-timeout 1 --max-time 3 -o /dev/null \
       -w '%{http_code}' http://checkout-api:8080/healthz 2>/dev/null || true)"
  if [[ ! "$code" =~ ^[0-9]{3}$ ]]; then
   echo "invalid HTTP probe status: '$code'" >&2
   exit 1
  fi
  printf '%d\n' "$((10#$code))" >> "$dir/$phase-probes.txt"
  sleep 0.25
 done
}
admin_snapshot() {
 kubectl -n golden-demo get svc checkout-api -o json > "$1"
}
observer_snapshot() {
 kubectl --kubeconfig="$OBS_CONFIG" -n golden-demo get svc checkout-api -o json > "$1"
}
evaluate() {
 local dir="$1" id="$2" scenario="$3" prediction_expected="$4" score_expected="$5"
 python3 demo/go-oracle/build_episode.py \
    --dir "$dir" --episode-id "$id" --scenario "$scenario" \
    --out "$dir/episode.json"
 /tmp/sre-agent-oracle diagnose-service \
    --observed-service "$dir/observed.json" --expected-target-port 8080 \
    --expected-selector app=checkout-api \
    --out "$dir/prediction.json"
 /tmp/sre-agent-oracle evaluate-oracle \
    --episode "$dir/episode.json" --prediction "$dir/prediction.json" \
    --out "$dir/evaluation.json"
 python3 - "$dir" "$prediction_expected" "$score_expected" <<'PY'
import base64, hashlib, json, pathlib, sys
directory=pathlib.Path(sys.argv[1])
episode=json.loads((directory/'episode.json').read_text())
prediction=json.loads((directory/'prediction.json').read_text())
score=json.loads((directory/'evaluation.json').read_text())
assert score['prediction']==sys.argv[2],score
assert score['verdict']==sys.argv[3],score
assert score['production_causality_verified'] is False,score
for part in ('before','during','after'):
    src=episode[part]
    raw=base64.b64decode(src['raw_response_base64'],validate=True)
    assert hashlib.sha256(raw).hexdigest()==src['response_sha256']
src=prediction['observed']
raw=base64.b64decode(src['raw_response_base64'],validate=True)
assert hashlib.sha256(raw).hexdigest()==src['response_sha256']
print('PASS: real independent kind Oracle and read-only baseline',episode['scenario'],score['verdict'])
PY
}

# Normal control: no injected fault; no false positive may escape.
CONTROL="$ROOT/control"
admin_snapshot "$CONTROL/before.json"
probe "$CONTROL" before
admin_snapshot "$CONTROL/during.json"
observer_snapshot "$CONTROL/observed.json"
probe "$CONTROL" during
admin_snapshot "$CONTROL/after.json"
probe "$CONTROL" after
evaluate "$CONTROL" control-001 NO_FAULT UNKNOWN CORRECT_REJECTION

# Fault episode: ONLY test administrator mutates Service targetPort.
FAULT="$ROOT/misroute"
admin_snapshot "$FAULT/before.json"
probe "$FAULT" before
kubectl -n golden-demo patch svc checkout-api --type=merge \
  -p '{"spec":{"ports":[{"port":8080,"targetPort":1}]}}'
admin_snapshot "$FAULT/during.json"
observer_snapshot "$FAULT/observed.json"
probe "$FAULT" during
kubectl -n golden-demo patch svc checkout-api --type=merge \
  -p '{"spec":{"ports":[{"port":8080,"targetPort":8080}]}}'
admin_snapshot "$FAULT/after.json"
probe "$FAULT" after
evaluate "$FAULT" fault-001 SERVICE_TARGETPORT_MISROUTED SERVICE_TARGETPORT_MISROUTED MATCHED_INJECTED_FAULT

# Second independent fault family: healthy app Pod and Service port remain
# stable; the test ADMIN points Service selector at a nonexistent label. The
# read-only observer sees only the Service during-fault response.
SELECTOR="$ROOT/selector"
admin_snapshot "$SELECTOR/before.json"
probe "$SELECTOR" before
kubectl -n golden-demo patch svc checkout-api --type=merge \
  -p '{"spec":{"selector":{"app":"checkout-no-match"}}}'
sleep 5 # allow EndpointSlice / kube-proxy update to converge
admin_snapshot "$SELECTOR/during.json"
observer_snapshot "$SELECTOR/observed.json"
probe "$SELECTOR" during
kubectl -n golden-demo patch svc checkout-api --type=merge \
  -p '{"spec":{"selector":{"app":"checkout-api"}}}'
sleep 5
admin_snapshot "$SELECTOR/after.json"
probe "$SELECTOR" after
evaluate "$SELECTOR" selector-001 SERVICE_SELECTOR_MISMATCH SERVICE_SELECTOR_MISMATCH MATCHED_INJECTED_FAULT

# Tamper negative checks: do not accept a forged label, a forged captured
# during snapshot, or a falsely claimed recovery. No failed evaluation file.
python3 - <<'PY'
import json,pathlib
d=pathlib.Path('/tmp/go-oracle-proof/misroute')
episode=json.loads((d/'episode.json').read_text())
prediction=json.loads((d/'prediction.json').read_text())
p=dict(prediction);p['classification']='UNKNOWN'
(d/'forged-prediction.json').write_text(json.dumps(p))
e=dict(episode);e['probes']=dict(episode['probes'])
e['probes']['after']=[0,0,0]
(d/'forged-recovery.json').write_text(json.dumps(e))
e=dict(episode);e['during']=dict(episode['during'])
e['during']['response_sha256']='0'*64
(d/'forged-source.json').write_text(json.dumps(e))
PY
for mode in prediction recovery source; do
 ep="$FAULT/episode.json"
 pred="$FAULT/prediction.json"
 case "$mode" in
  prediction) pred="$FAULT/forged-prediction.json" ;;
  recovery) ep="$FAULT/forged-recovery.json" ;;
  source) ep="$FAULT/forged-source.json" ;;
 esac
 set +e
 /tmp/sre-agent-oracle evaluate-oracle --episode "$ep" --prediction "$pred" \
  --out "$FAULT/forged-$mode-result.json" >"$FAULT/forged-$mode-stderr.txt" 2>&1
 result=$?
 set -e
 test "$result" -eq 3
 test ! -f "$FAULT/forged-$mode-result.json"
 grep -q UNKNOWN "$FAULT/forged-$mode-stderr.txt"
 echo "PASS: rejected forged $mode Oracle evidence"
done

# Explicitly prove the temporary test cluster was restored.
test "$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.ports[0].targetPort}')" = 8080
 test "$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.selector.app}')" = checkout-api
echo "PASS: restored original Service targetPort; observer never had writes"
