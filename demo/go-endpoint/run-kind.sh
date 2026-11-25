#!/usr/bin/env bash
# G2g: disposable kind ONLY. All Deployment scaling below is test-admin
# injection. SRE Agent owns only GET Service / LIST EndpointSlice in this lab.
set -euo pipefail
ROOT=/tmp/go-endpoint-proof
# A proof directory belongs to exactly one run; never follow an existing
# path or mix prior evidence with a new incident before touching Kubernetes.
if ! (umask 077; mkdir -m 0700 "$ROOT"); then
  echo "FAIL: Endpoint proof root already exists or cannot be created: $ROOT" >&2
  exit 1
fi
(umask 077; mkdir -m 0700 "$ROOT/control" "$ROOT/no-ready")
kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-endpoint/reader-role.yaml
kubectl -n golden-demo rollout status deploy/checkout-api --timeout=180s
kubectl -n golden-demo scale deploy/load-generator --replicas=1
kubectl -n golden-demo rollout status deploy/load-generator --timeout=120s
SRE_AGENT_BIN=/tmp/sre-agent-g2g
go build -o "$SRE_AGENT_BIN" ./cmd/sre-agent

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

# The CLI deliberately accepts no Kubernetes token. kubectl proxy authenticates
# with the disposable read-only kubeconfig and exposes only a loopback endpoint.
PROXY_PID=""
restore() {
  if [[ -n "$PROXY_PID" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  kubectl -n golden-demo scale deploy/checkout-api --replicas=2 >/dev/null 2>&1 || true
  rm -f "$OBS" /tmp/go-endpoint-ca.crt
}
trap restore EXIT

kubectl --kubeconfig="$OBS" proxy --address=127.0.0.1 --port=18001 >/tmp/go-endpoint-kube-proxy.log 2>&1 &
PROXY_PID=$!
for attempt in $(seq 1 30); do
  if curl --noproxy '*' -fsS http://127.0.0.1:18001/api/v1/namespaces/golden-demo/services/checkout-api >/dev/null; then break; fi
  sleep 1
done
curl --noproxy '*' -fsS http://127.0.0.1:18001/api/v1/namespaces/golden-demo/services/checkout-api >/dev/null || {
  cat /tmp/go-endpoint-kube-proxy.log >&2
  exit 1
}

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
capture_observer() {
  local dir="$1" uid capture pin
  uid="$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.metadata.uid}')" || return 1
  capture="$dir/observer-capture.json"
  # Create-only, private capture/pin/receipt files. The lab pin records local
  # byte continuity immediately after capture, not independent provenance.
  (umask 077; set -o noclobber
    "$SRE_AGENT_BIN" capture-service-endpoints --namespace golden-demo --service checkout-api --uid "$uid" --kube-api http://127.0.0.1:18001 --expected-target-port 8080 --expected-selector app=checkout-api --timeout 15s > "$capture" &&
    python3 demo/go-endpoint/check_replay.py pin "$capture" > "$dir/observer-capture.sha256"
  ) || return 1
  pin="$(cat "$dir/observer-capture.sha256")" || return 1
  (umask 077; set -o noclobber
    "$SRE_AGENT_BIN" replay-service-endpoints --capture "$capture" --sha256 "$pin" \
      --namespace golden-demo --service checkout-api --uid "$uid" \
      --expected-target-port 8080 --expected-selector app=checkout-api > "$dir/observer-replay.json"
  ) || return 1
  python3 demo/go-endpoint/verify_capture.py "$capture" "$dir" "$uid"
}

ready_count() {
  local file="$1" prediction
  service admin "$file.service.json" || return 1
  prediction="$("$SRE_AGENT_BIN" diagnose-endpoints \
    --observed-service "$file.service.json" --observed-endpointslices "$file" \
    --expected-target-port 8080 --expected-selector app=checkout-api --out -)" || return $?
  printf '%s\n' "$prediction" | python3 -c '
import json, sys
p = json.load(sys.stdin)
if not isinstance(p, dict) or p.get("schema_version") != "sre.endpoint-observation/v1":
    sys.exit(1)
count = p.get("ready_endpoints")
if type(count) is not int or not 0 <= count <= 128 * 256:
    sys.exit(1)
classification = p.get("classification")
if classification == "UNKNOWN":
    sys.exit(3)
if classification != ("READY_ENDPOINTS_OBSERVED" if count else "NO_READY_ENDPOINTS_OBSERVED"):
    sys.exit(1)
print(count)
'
}
wait_ready() {
  local goal="$1" file="$2" n count rc
  for n in $(seq 1 75); do
    slices admin "$file" || return 1
    if count="$(ready_count "$file")"; then
      if [[ "$goal" == "positive" && "$count" -gt 0 ]] || [[ "$goal" == "zero" && "$count" -eq 0 ]]; then
        echo "EndpointSlice Ready endpoints: $count ($goal)"
        return 0
      fi
    else
      rc=$?
      if [[ "$rc" -ne 3 ]]; then return "$rc"; fi
      echo "UNKNOWN: preflight sample not admissible; waiting for steady state" >&2
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
    kubectl get --raw '/api/v1/namespaces/golden-demo/pods?labelSelector=app%3Dcheckout-api&limit=1' > "$file" || return 1
    if python3 - "$file" <<'PY'
import json,sys
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key]=value
    return result

def canonical(obj,fields):
    names={key.casefold():key for key in fields}
    return all(key.casefold() not in names or names[key.casefold()]==key for key in obj)

try:
    with open(sys.argv[1],"rb") as stream:
        raw=stream.read((2<<20)+1)
    if len(raw)>2<<20:
        sys.exit(1)
    p=json.loads(raw.decode("utf-8"),object_pairs_hook=unique)
except (ValueError,OSError,RecursionError):
    sys.exit(1)
if not isinstance(p,dict) or p.get("kind")!="PodList" or p.get("apiVersion")!="v1":
    sys.exit(1)
if not canonical(p,("apiVersion","kind","metadata","items")):
    sys.exit(1)
m=p.get("metadata")
if not isinstance(m,dict) or not canonical(m,("resourceVersion","continue","remainingItemCount")):
    sys.exit(1)
rv=m.get("resourceVersion")
remaining=m.get("remainingItemCount",0)
try:
    valid_rv=isinstance(rv,str) and rv not in ("","0") and len(rv.encode("utf-8"))<=256
except UnicodeError:
    valid_rv=False
complete=(valid_rv and
          m.get("continue","")=="" and type(remaining) is int and remaining==0)
sys.exit(0 if complete and p.get("items")==[] else 1)
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
  local result
  # Separate kubectl exec transport from the completed remote curl process.
  result="$(kubectl -n golden-demo exec deploy/load-generator -c load -- sh -c '
    rc=0
    status=$(curl --noproxy "*" -sS --connect-timeout 1 --max-time 3 -o /dev/null \
      -w "%{http_code}" http://checkout-api:8080/healthz) || rc=$?
    printf "%s:%s\n" "$rc" "$status"
  ')" || { echo "probe exec failed" >&2; return 1; }
  case "$result" in
    0:[1-5][0-9][0-9]) printf '%s\n' "${result#*:}" ;;
    7:000|28:000) printf '0\n' ;;
    *) echo "probe did not return admissible HTTP evidence" >&2; return 1 ;;
  esac
}
wait_http_failure() {
  local file="$1" i code consecutive=0
  : > "$file"
  for i in $(seq 1 45); do
    code="$(probe_one)" || return 1
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
# An ordinary fresh LIST may move to a different cluster resourceVersion
# between the test-admin and observer reads. Do not weaken the Go Oracle
# equality gate or cherry-pick an alternative "during" sample. The observer
# reads first; the independent test-admin then re-reads the *same* list using
# Kubernetes resourceVersionMatch=Exact. Both original files are archived.
snapshot_during() {
  local dir="$1" exact_path
  capture_observer "$dir"
  exact_path="$(python3 demo/go-endpoint/pin_during.py "$dir/observed-endpointslices.json")"
  service admin "$dir/during-service.json"
  kubectl get --raw "$exact_path" > "$dir/during-endpointslices.json"
  python3 demo/go-endpoint/pin_during.py --verify \
    "$dir/observed-endpointslices.json" "$dir/during-endpointslices.json"
}
probe() {
  local dir="$1" phase="$2" n code
  : > "$dir/$phase-probes.txt"
  for n in 1 2 3; do
    code="$(probe_one)" || return 1
    printf '%s\n' "$code" >> "$dir/$phase-probes.txt"
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
 # The same archive must survive replay and agree with the separate native
 # prediction before an independent episode can receive a verdict.
 python3 demo/go-endpoint/check_replay.py verify \
   "$dir/observer-capture.json" "$dir/observer-capture.sha256" \
   "$dir/observer-replay.json" "$dir/prediction.json" || return 1
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
assert score['episode_sha256']==hashlib.sha256((p/'episode.json').read_bytes()).hexdigest()
assert score['prediction_sha256']==hashlib.sha256((p/'prediction.json').read_bytes()).hexdigest()
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
snapshot_during "$CONTROL"
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
snapshot_during "$FAULT"
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

# Inventory only after both cases, forged-input checks and recovery checks.
manifest="$(python3 demo/go-endpoint/incident_manifest.py build "$ROOT")"
(umask 077; set -o noclobber; printf '%s\n' "$manifest" > "$ROOT/incident-manifest.json")
python3 demo/go-endpoint/incident_manifest.py verify "$ROOT"
