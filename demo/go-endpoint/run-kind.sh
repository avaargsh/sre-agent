#!/usr/bin/env bash
# G2g: disposable kind ONLY. All Deployment scaling below is test-admin
# injection. SRE Agent owns only GET Service / LIST EndpointSlice in this lab.
set -euo pipefail
ROOT=/tmp/go-endpoint-proof
mkdir -p "$ROOT/control" "$ROOT/no-ready"
chmod 0700 "$ROOT"
kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-endpoint/reader-role.yaml
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
kubectl -n golden-demo scale deploy/load-generator --replicas=1
kubectl -n golden-demo rollout status deploy/load-generator --timeout=120s
go build -o /tmp/sre-agent-g2g ./cmd/sre-agent

SA=system:serviceaccount:golden-demo:sre-endpoint-reader
test "$(kubectl auth can-i get services/checkout-api --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i list endpointslices.discovery.k8s.io --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i patch deploy/checkout-api --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i patch services/checkout-api --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list secrets --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list pods --as="$SA" -n golden-demo)" = no

SERVER="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/go-endpoint-ca.crt
TOKEN="$(kubectl -n golden-demo create token sre-endpoint-reader --duration=10m)"
OBS=/tmp/go-endpoint-observer.kubeconfig
kubectl config --kubeconfig="$OBS" set-cluster endpoint-kind --server="$SERVER" --certificate-authority=/tmp/go-endpoint-ca.crt --embed-certs=true >/dev/null
kubectl config --kubeconfig="$OBS" set-credentials observer --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$OBS" set-context observer --cluster=endpoint-kind --user=observer >/dev/null
kubectl config --kubeconfig="$OBS" use-context observer >/dev/null
chmod 0600 "$OBS"
restore() {
  kubectl -n golden-demo scale deploy/checkout-api --replicas=2 >/dev/null 2>&1 || true
  rm -f "$OBS" /tmp/go-endpoint-ca.crt
}
trap restore EXIT

# kubectl resource-printer JSON returns a generic List with empty RV;
# use the actual discovery.k8s.io LIST API for an auditable collection RV
# and explicit pagination. Never weaken source replay to accept empty RV.
EP_PATH='/apis/discovery.k8s.io/v1/namespaces/golden-demo/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dcheckout-api&limit=129'
slices() {
  local auth="$1" dest="$2"
  if [[ "$auth" == "admin" ]]; then
    kubectl get --raw "$EP_PATH" > "$dest"
  else
    kubectl --kubeconfig="$OBS" get --raw "$EP_PATH" > "$dest"
  fi
}
service() {
  local auth="$1" dest="$2"
  if [[ "$auth" == "admin" ]]; then
    kubectl -n golden-demo get svc checkout-api -o json > "$dest"
  else
    kubectl --kubeconfig="$OBS" -n golden-demo get svc checkout-api -o json > "$dest"
  fi
}
ready_count() {
  python3 - "$1" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data.get('kind')=='EndpointSliceList'
assert data['metadata']['resourceVersion']
assert not data['metadata'].get('continue')
items=data['items']
assert len(items)<=128
total=0
for item in items:
  assert item['metadata']['namespace']=='golden-demo'
  assert item['metadata']['labels']['kubernetes.io/service-name']=='checkout-api'
  for endpoint in item.get('endpoints',[]):
    assert isinstance(endpoint.get('conditions',{}).get('ready'),bool)
    total+=int(endpoint['conditions']['ready'])
print(total)
PY
}
wait_ready() {
  local goal="$1" file="$2" n count
  for n in $(seq 1 75); do
    slices admin "$file"
    count="$(ready_count "$file")"
    if [[ "$goal" == "positive" && "$count" -gt 0 ]] || [[ "$goal" == "zero" && "$count" -eq 0 ]]; then
      echo "EndpointSlice Ready endpoints: $count ($goal)"
      return 0
    fi
    sleep 2
  done
  echo "EndpointSlice readiness never converged to $goal" >&2
  return 1
}
# EndpointSlice convergence alone is NOT enough to establish a dataplane outage.
# Wait for the old checkout Pod objects to disappear and record that evidence.
wait_zero_pods() {
  local file="$1" i
  for i in $(seq 1 75); do
    kubectl -n golden-demo get pods -l app=checkout-api -o json > "$file"
    if python3 - "$file" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
assert p.get("kind")=="PodList"
sys.exit(0 if len(p.get("items",[]))==0 else 1)
PY
    then
      echo "PASS: test-admin observed zero checkout Pods"
      return 0
    fi
    sleep 2
  done
  echo "FAIL: checkout Pod deletion did not converge" >&2
  return 1
}
# Keep *all* warm-up probes as evidence; begin official fault samples only
# after three consecutive real client failures (no quiet cherry-picking).
probe_one() {
  local status
  status="$(kubectl -n golden-demo exec deploy/load-generator -c load -- \
    curl --noproxy '*' -sS --connect-timeout 1 --max-time 3 -o /dev/null \
      -w '%{http_code}' http://checkout-api:8080/healthz 2>/dev/null || true)"
  [[ "$status" =~ ^[0-9]{3}$ ]] || { echo "invalid curl status: $status" >&2; return 1; }
  printf '%d\n' "$((10#$status))"
}
wait_http_failure() {
  local file="$1" i code consecutive=0
  : > "$file"
  for i in $(seq 1 45); do
    code="$(probe_one)"
    printf '%s\n' "$code" >> "$file"
    if (( code<200 || code>=300 )); then
      consecutive=$((consecutive+1))
    else
      consecutive=0
    fi
    if (( consecutive>=3 )); then
      echo "PASS: independent client observed three consecutive HTTP failures"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: EndpointSlice empty but real HTTP requests remained successful" >&2
  return 1
}

snapshot() {
  local dir="$1" phase="$2"
  service admin "$dir/$phase-service.json"
  slices admin "$dir/$phase-endpointslices.json"
}
probe() {
  local dir="$1" phase="$2" n code
  : > "$dir/$phase-probes.txt"
  for n in 1 2 3; do
    code="$(kubectl -n golden-demo exec deploy/load-generator -c load -- \
      curl --noproxy '*' -sS --connect-timeout 1 --max-time 3 -o /dev/null \
      -w '%{http_code}' http://checkout-api:8080/healthz 2>/dev/null || true)"
    [[ "$code" =~ ^[0-9]{3}$ ]] || { echo "invalid curl status: $code" >&2; return 1; }
    printf '%d\n' "$((10#$code))" >> "$dir/$phase-probes.txt"
    sleep 0.25
  done
}
judge() {
 local dir="$1" id="$2" scenario="$3" want="$4" verdict="$5"
 # Admin-only frozen episode; observer never sees its label or probes.
 python3 - "$dir" "$id" "$scenario" <<'PY'
import base64,hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
def evidence(path):
  raw=path.read_bytes()
  assert 0<len(raw)<=2*1024*1024
  return {'response_sha256':hashlib.sha256(raw).hexdigest(),
          'raw_response_base64':base64.b64encode(raw).decode('ascii')}
def phase(name):
  return {'service':evidence(p/(name+'-service.json')),
          'endpoint_slices':evidence(p/(name+'-endpointslices.json')),
          'probes':[int(s) for s in (p/(name+'-probes.txt')).read_text().splitlines()]}
meta=json.loads((p/'before-service.json').read_text())['metadata']
episode={
  'schema_version':'sre.endpoint-oracle/v1',
  'episode_id':sys.argv[2],'scenario':sys.argv[3],
  'namespace':meta['namespace'],'service':meta['name'],'service_uid':meta['uid'],
  'expected_target_port':8080,'expected_selector':{'app':'checkout-api'},
  'before':phase('before'),'during':phase('during'),'after':phase('after')
}
(p/'episode.json').write_text(json.dumps(episode,sort_keys=True,indent=2)+'\n')
PY
 /tmp/sre-agent-g2g diagnose-endpoints \
   --observed-service "$dir/observed-service.json" \
   --observed-endpointslices "$dir/observed-endpointslices.json" \
   --expected-target-port 8080 --expected-selector app=checkout-api \
   --out "$dir/prediction.json"
 /tmp/sre-agent-g2g evaluate-endpoints \
   --episode "$dir/episode.json" --prediction "$dir/prediction.json" \
   --out "$dir/evaluation.json"
 python3 - "$dir" "$want" "$verdict" <<'PY'
import base64,hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
e=json.loads((p/'episode.json').read_text())
pred=json.loads((p/'prediction.json').read_text())
score=json.loads((p/'evaluation.json').read_text())
assert pred['classification']==sys.argv[2],pred
assert score['verdict']==sys.argv[3],score
assert score['production_causality_verified']==False
for phase in ('before','during','after'):
  for field in ('service','endpoint_slices'):
    src=e[phase][field]
    raw=base64.b64decode(src['raw_response_base64'],validate=True)
    assert hashlib.sha256(raw).hexdigest()==src['response_sha256']
for field in ('service','endpoint_slices'):
  src=pred['service']['observed'] if field=='service' else pred['endpoint_slices']
  raw=base64.b64decode(src['raw_response_base64'],validate=True)
  assert hashlib.sha256(raw).hexdigest()==src['response_sha256']
print('PASS: genuine EndpointSlice+Service read-only oracle',e['scenario'],score['verdict'])
PY
}

# Control: READY endpoints present and all real requests succeed.
CONTROL="$ROOT/control"
wait_ready positive "$CONTROL/preflight.json"
snapshot "$CONTROL" before
probe "$CONTROL" before
snapshot "$CONTROL" during
service observer "$CONTROL/observed-service.json"
slices observer "$CONTROL/observed-endpointslices.json"
probe "$CONTROL" during
snapshot "$CONTROL" after
probe "$CONTROL" after
judge "$CONTROL" endpoint-control-001 NO_FAULT READY_ENDPOINTS_OBSERVED CORRECT_CONTROL

# Fault: admin scales *Deployment* to zero; Service port and selector remain
# unchanged. This proves loss of ready endpoints, not its production root cause.
FAULT="$ROOT/no-ready"
snapshot "$FAULT" before
probe "$FAULT" before
kubectl -n golden-demo scale deploy/checkout-api --replicas=0
wait_ready zero "$FAULT/preflight-zero.json"
wait_zero_pods "$FAULT/zero-pods.json"
wait_http_failure "$FAULT/convergence-probes.txt"
snapshot "$FAULT" during
service observer "$FAULT/observed-service.json"
slices observer "$FAULT/observed-endpointslices.json"
probe "$FAULT" during
kubectl -n golden-demo scale deploy/checkout-api --replicas=2
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
wait_ready positive "$FAULT/preflight-recovered.json"
snapshot "$FAULT" after
probe "$FAULT" after
judge "$FAULT" endpoint-fault-001 NO_READY_ENDPOINTS NO_READY_ENDPOINTS_OBSERVED MATCHED_INJECTED_OUTAGE

python3 - <<'PY'
import json,pathlib
base=pathlib.Path('/tmp/go-endpoint-proof/no-ready')
e=json.loads((base/'episode.json').read_text())
p=json.loads((base/'prediction.json').read_text())
bad=dict(p);bad['ready_endpoints']=99
(base/'forged-count.json').write_text(json.dumps(bad))
bad=dict(e);bad['after']=dict(e['after']);bad['after']['probes']=[0,0,0]
(base/'forged-recovery.json').write_text(json.dumps(bad))
bad=dict(e);bad['during']=dict(e['during'])
bad['during']['endpoint_slices']=dict(e['during']['endpoint_slices'])
bad['during']['endpoint_slices']['response_sha256']='0'*64
(base/'forged-digest.json').write_text(json.dumps(bad))
PY
for variant in count recovery digest; do
  episode="$FAULT/episode.json"
  prediction="$FAULT/prediction.json"
  case "$variant" in
    count) prediction="$FAULT/forged-count.json" ;;
    recovery) episode="$FAULT/forged-recovery.json" ;;
    digest) episode="$FAULT/forged-digest.json" ;;
  esac
  set +e
  /tmp/sre-agent-g2g evaluate-endpoints --episode "$episode" --prediction "$prediction" \
    --out "$FAULT/forged-$variant-evaluation.json" > "$FAULT/forged-$variant-log.txt" 2>&1
  rc=$?
  set -e
  test "$rc" -eq 3
  test ! -f "$FAULT/forged-$variant-evaluation.json"
  grep -q UNKNOWN "$FAULT/forged-$variant-log.txt"
  echo "PASS: forged EndpointSlice $variant failed closed"
done

test "$(kubectl -n golden-demo get deploy checkout-api -o jsonpath='{.spec.replicas}')" = 2
test "$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.ports[0].targetPort}')" = 8080
test "$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.selector.app}')" = checkout-api
echo "PASS: test-only backend scaled back up; no SRE Agent write permission"
