#!/usr/bin/env bash
# Executes real NetworkPolicy fault injection in disposable kind+Calico.
# Test-admin performs all writes. SRE observer can only GET named Pod logs.
set -euo pipefail
ROOT=/tmp/go-networkpolicy-proof
mkdir -p "$ROOT"
chmod 0700 "$ROOT"

# Fail if the cluster is using kind's default CNI. A YAML policy alone
# cannot prove real enforcement.
kubectl -n kube-system get daemonset/calico-node -o json > "$ROOT/calico-node-ds.json"
if kubectl -n kube-system get daemonset/kindnet >/dev/null 2>&1; then
  echo "FAIL: kindnet is installed; cannot claim NetworkPolicy enforcement" >&2
  exit 1
fi
kubectl -n kube-system rollout status daemonset/calico-node --timeout=240s
kubectl wait nodes --all --for=condition=Ready --timeout=240s
kubectl get nodes -o json > "$ROOT/kind-ready-nodes.json"

kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-networkpolicy/reader-role.yaml
kubectl -n golden-demo rollout status deployment/checkout-api --timeout=240s
SERVICE_IP="$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.clusterIP}')"
test -n "$SERVICE_IP"
SERVICE_HOST=checkout-api.golden-demo.svc.cluster.local
kubectl -n golden-demo create configmap sre-np-probe-source \
  --from-file=probe.py=demo/go-networkpolicy/probe.py \
  --dry-run=client -o yaml | kubectl apply -f -

# Native Kubernetes LIST endpoints retain collection ResourceVersion and
# pagination fields (kubectl get -o json produces a generic unversioned List).
EPS_URL='/apis/discovery.k8s.io/v1/namespaces/golden-demo/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dcheckout-api&limit=129'
POLICY_URL='/apis/networking.k8s.io/v1/namespaces/golden-demo/networkpolicies?limit=10'
snapshot() {
  local stage="$1"
  kubectl -n golden-demo get svc checkout-api -o json > "$ROOT/$stage-service.json"
  kubectl get --raw "$EPS_URL" > "$ROOT/$stage-endpoint-slices.json"
  kubectl get --raw "$POLICY_URL" > "$ROOT/$stage-network-policies.json"
  kubectl -n golden-demo get pod "np-$stage" -o json > "$ROOT/$stage-pod.json"
  kubectl -n golden-demo logs "pod/np-$stage" -c probe > "$ROOT/$stage-admin.log"
}

make_probe_pod() {
  local stage="$1"
  cat >"/tmp/g2i-$stage-pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: np-$stage
  namespace: golden-demo
  labels:
    app: sre-np-probe
spec:
  automountServiceAccountToken: false
  dnsPolicy: ClusterFirst
  restartPolicy: Never
  containers:
  - name: probe
    image: python:3.12-slim
    command: ["python", "/probe/probe.py"]
    env:
    - name: SERVICE_HOST
      value: "$SERVICE_HOST"
    - name: SERVICE_IP
      value: "$SERVICE_IP"
    - name: PROBE_PHASE
      value: "$stage"
    resources:
      requests: {cpu: 20m, memory: 32Mi}
      limits: {cpu: "1", memory: 128Mi}
    volumeMounts:
    - name: probe-source
      mountPath: /probe
  volumes:
  - name: probe-source
    configMap:
      name: sre-np-probe-source
EOF
  kubectl apply -f "/tmp/g2i-$stage-pod.yaml"
  kubectl -n golden-demo wait "pod/np-$stage" --for=jsonpath='{.status.phase}'=Succeeded --timeout=180s
  snapshot "$stage"
}

# Admin baseline: prove the connection is functioning before any policy
# is present. The first Pod cannot be falsely assumed to be ready.
make_probe_pod before
python3 - "$ROOT/before-admin.log" "$SERVICE_IP" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d['dns_ok'] is True and sys.argv[2] in d['dns_addresses'],d
assert d['name_http_status']==200 and d['direct_http_attempts']==[200,200,200],d
print('PASS: actual healthy DNS and three direct-IP HTTP 200s, before injection')
PY

# ONLY the CI test admin mutates NetworkPolicy. DNS TCP/UDP port 53 remains
# allowed; the Service, EndpointSlices and backend are not modified.
kubectl apply -f demo/go-networkpolicy/deny-http.yaml
sleep 6
make_probe_pod during
python3 - "$ROOT/during-admin.log" "$SERVICE_IP" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d['dns_ok'] is True and sys.argv[2] in d['dns_addresses'],d
assert d['name_http_status']==0 and d['direct_http_attempts']==[0,0,0],d
print('PASS: DNS still healthy, real NetworkPolicy egress drops HTTP three times')
PY

# Restore the original policy-free dataplane and independently prove that
# connections recover. A probe failure after deletion fails the run.
kubectl -n golden-demo delete networkpolicy sre-g2i-deny-http --wait=true
sleep 6
make_probe_pod after
python3 - "$ROOT/after-admin.log" "$SERVICE_IP" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d['dns_ok'] is True and sys.argv[2] in d['dns_addresses'],d
assert d['name_http_status']==200 and d['direct_http_attempts']==[200,200,200],d
print('PASS: original DNS+HTTP reachability restored after admin policy deletion')
PY

# Restricted observer: no Pod creation, no exec, no mutation, no Secret read.
SA=system:serviceaccount:golden-demo:sre-np-reader
test "$(kubectl auth can-i get pods/np-before --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i get pods/np-during --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i get pods/np-after --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i create pods --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i create pods/exec --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i patch networkpolicies --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list networkpolicies --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list secrets --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list pods --as="$SA" -n golden-demo)" = no

SERVER="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/g2i-ca.crt
TOKEN="$(kubectl -n golden-demo create token sre-np-reader --duration=10m)"
OBSCONFIG=/tmp/g2i-restricted.kubeconfig
kubectl config --kubeconfig="$OBSCONFIG" set-cluster restricted --server="$SERVER" --certificate-authority=/tmp/g2i-ca.crt --embed-certs=true >/dev/null
kubectl config --kubeconfig="$OBSCONFIG" set-credentials observer --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$OBSCONFIG" set-context observer --cluster=restricted --user=observer >/dev/null
kubectl config --kubeconfig="$OBSCONFIG" use-context observer >/dev/null
chmod 0600 "$OBSCONFIG"
trap 'rm -f "$OBSCONFIG" /tmp/g2i-ca.crt' EXIT

go build -o /tmp/sre-agent-networkpolicy ./cmd/sre-agent
for stage in before during after; do
  kubectl --kubeconfig="$OBSCONFIG" -n golden-demo logs "pod/np-$stage" -c probe > "$ROOT/$stage-observer.log"
  /tmp/sre-agent-networkpolicy diagnose-dns --probe "$ROOT/$stage-observer.log" \
    --out "$ROOT/$stage-observation.json"
done

# Admin-only source packager: hold until ALL observer predictions frozen.
python3 demo/go-networkpolicy/build_episode.py --directory "$ROOT"
/tmp/sre-agent-networkpolicy evaluate-networkpolicy \
  --episode "$ROOT/episode.json" \
  --before "$ROOT/before-observation.json" \
  --during "$ROOT/during-observation.json" \
  --after "$ROOT/after-observation.json" \
  --out "$ROOT/evaluation.json"

python3 - <<'PY'
import base64,hashlib,json,pathlib
p=pathlib.Path('/tmp/go-networkpolicy-proof')
episode=json.loads((p/'episode.json').read_text())
result=json.loads((p/'evaluation.json').read_text())
assert result['status']=='MATCHED_LAB_NETWORK_POLICY_DENIAL'
assert result['production_causality_verified'] is False
assert result['during_diagnostic']=='UNKNOWN'
for stage in ('before','during','after'):
    assert (p/(stage+'observer.log')).read_bytes()==(p/(stage+'admin.log')).read_bytes()
    for name in ('probe','pod','service','endpoint_slices','network_policy_list'):
        item=episode[stage][name]
        raw=base64.b64decode(item['raw_response_base64'],validate=True)
        assert hashlib.sha256(raw).hexdigest()==item['response_sha256']
    obs=json.loads((p/(stage+'observation.json')).read_text())['observed']
    raw=base64.b64decode(obs['raw_response_base64'],validate=True)
    assert hashlib.sha256(raw).hexdigest()==obs['response_sha256']
print('PASS: fifteen original frozen admin sources and three separate observer logs verified')
PY

# Negative adversarial admin-side evidence, including a forged policy that
# recomputes its SHA so it can only be caught by semantic policy validation.
python3 - <<'PY'
import base64,hashlib,json,pathlib
root=pathlib.Path('/tmp/go-networkpolicy-proof')
e=json.loads((root/'episode.json').read_text())
obs=json.loads((root/'during-observation.json').read_text())
fake=dict(obs);fake['classification']='NETWORK_POLICY_CONFIRMED'
(root/'forged-observer.json').write_text(json.dumps(fake))
fake=json.loads(json.dumps(e))
fake['during']['network_policy_list']=fake['before']['network_policy_list']
(root/'forged-absent-policy.json').write_text(json.dumps(fake))
fake=json.loads(json.dumps(e))
snapshot=fake['during']['network_policy_list']
raw=json.loads(base64.b64decode(snapshot['raw_response_base64']))
raw['items'][0]['spec']['egress'][0]['ports'].append({'protocol':'TCP','port':8080})
wire=json.dumps(raw,sort_keys=True,separators=(',',':')).encode()
snapshot['raw_response_base64']=base64.b64encode(wire).decode()
snapshot['response_sha256']=hashlib.sha256(wire).hexdigest()
(root/'forged-allow-8080.json').write_text(json.dumps(fake))
fake=json.loads(json.dumps(e))
fake['during']['endpoint_slices']['response_sha256']='0'*64
(root/'forged-endpoint-sha.json').write_text(json.dumps(fake))
PY
for variant in observer absent-policy allow-8080 endpoint-sha; do
  EP="$ROOT/episode.json"
  DUR="$ROOT/during-observation.json"
  case "$variant" in
    observer) DUR="$ROOT/forged-observer.json" ;;
    absent-policy) EP="$ROOT/forged-absent-policy.json" ;;
    allow-8080) EP="$ROOT/forged-allow-8080.json" ;;
    endpoint-sha) EP="$ROOT/forged-endpoint-sha.json" ;;
  esac
  set +e
  /tmp/sre-agent-networkpolicy evaluate-networkpolicy \
    --episode "$EP" --before "$ROOT/before-observation.json" \
    --during "$DUR" --after "$ROOT/after-observation.json" \
    --out "$ROOT/forged-$variant-output.json" >"$ROOT/forged-$variant.log" 2>&1
  code=$?
  set -e
  test "$code" -eq 3
  test ! -f "$ROOT/forged-$variant-output.json"
  grep -q UNKNOWN "$ROOT/forged-$variant.log"
  echo "PASS: forged $variant cannot pass independent NetworkPolicy oracle"
done

echo "PASS: real Calico policy deny/restore, DNS still working, backend Ready, no Agent write"
