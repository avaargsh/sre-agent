#!/usr/bin/env bash
# G2h - run ONLY inside a disposable kind cluster. All Pod creation is done
# by CI test admin. The SRE observer owns only GET on two named Pod logs.
set -euo pipefail
ROOT=/tmp/go-dns-proof
mkdir -p "$ROOT"
chmod 0700 "$ROOT"

kubectl apply -f demo/k8s/golden-stack.yaml
kubectl apply -f demo/go-dns/reader-role.yaml
kubectl -n golden-demo rollout status deployment/checkout-api --timeout=180s

SERVICE_IP="$(kubectl -n golden-demo get svc checkout-api -o jsonpath='{.spec.clusterIP}')"
SERVICE_HOST=checkout-api.golden-demo.svc.cluster.local
test -n "$SERVICE_IP"

# Test-admin deliberately configures different resolvers for otherwise
# identical one-shot probes. Neither probe gets a ServiceAccount token.
kubectl -n golden-demo create configmap sre-dns-probe-script \
  --from-file=probe.py=demo/go-dns/probe.py \
  --dry-run=client -o yaml | kubectl apply -f -
cat >/tmp/sre-dns-client-pods.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: dns-good
  namespace: golden-demo
spec:
  automountServiceAccountToken: false
  dnsPolicy: ClusterFirst
  restartPolicy: Never
  containers:
    - name: probe
      image: python:3.12-slim
      command: ["python", "/probe/probe.py"]
      resources:
        requests: {cpu: 20m, memory: 32Mi}
        limits: {cpu: "1", memory: 128Mi}
      env:
        - name: SERVICE_HOST
          value: "$SERVICE_HOST"
        - name: SERVICE_IP
          value: "$SERVICE_IP"
      volumeMounts:
        - name: probe-source
          mountPath: /probe
  volumes:
    - name: probe-source
      configMap:
        name: sre-dns-probe-script
---
apiVersion: v1
kind: Pod
metadata:
  name: dns-bad
  namespace: golden-demo
spec:
  automountServiceAccountToken: false
  dnsPolicy: None
  dnsConfig:
    nameservers: ["127.0.0.1"]
    options:
      - name: timeout
        value: "1"
      - name: attempts
        value: "1"
  restartPolicy: Never
  containers:
    - name: probe
      image: python:3.12-slim
      command: ["python", "/probe/probe.py"]
      resources:
        requests: {cpu: 20m, memory: 32Mi}
        limits: {cpu: "1", memory: 128Mi}
      env:
        - name: SERVICE_HOST
          value: "$SERVICE_HOST"
        - name: SERVICE_IP
          value: "$SERVICE_IP"
      volumeMounts:
        - name: probe-source
          mountPath: /probe
  volumes:
    - name: probe-source
      configMap:
        name: sre-dns-probe-script
EOF
kubectl apply -f /tmp/sre-dns-client-pods.yaml
kubectl -n golden-demo wait pod/dns-good --for=jsonpath='{.status.phase}'=Succeeded --timeout=180s
kubectl -n golden-demo wait pod/dns-bad --for=jsonpath='{.status.phase}'=Succeeded --timeout=180s

# Freeze test-admin configuration evidence, separate from SRE observer logs.
kubectl -n golden-demo get svc checkout-api -o json > "$ROOT/admin-service.json"
kubectl -n golden-demo get pod dns-good -o json > "$ROOT/admin-dns-good-pod.json"
kubectl -n golden-demo get pod dns-bad -o json > "$ROOT/admin-dns-bad-pod.json"
kubectl -n golden-demo logs pod/dns-good -c probe > "$ROOT/admin-dns-good.log"
kubectl -n golden-demo logs pod/dns-bad -c probe > "$ROOT/admin-dns-bad.log"

# The log observer uses a different kubeconfig with *only* named Pod read.
SA=system:serviceaccount:golden-demo:sre-dns-reader
test "$(kubectl auth can-i get pods/dns-good --as="$SA" -n golden-demo)" = yes
test "$(kubectl auth can-i get pods/dns-bad --as="$SA" -n golden-demo)" = yes
# kubectl auth can-i has no --resource-name switch in this version. Use
# the actual restricted bearer-token log GET calls below as positive proof.
test "$(kubectl auth can-i get secrets --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i list pods --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i create pods --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i create pods/exec --as="$SA" -n golden-demo)" = no
test "$(kubectl auth can-i patch pods --as="$SA" -n golden-demo)" = no

API="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /tmp/go-dns-ca.crt
TOKEN="$(kubectl -n golden-demo create token sre-dns-reader --duration=10m)"
OBS_CONFIG=/tmp/go-dns-observer.kubeconfig
kubectl config --kubeconfig="$OBS_CONFIG" set-cluster read-only-kind --server="$API" --certificate-authority=/tmp/go-dns-ca.crt --embed-certs=true >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" set-credentials observer --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" set-context observer --cluster=read-only-kind --user=observer >/dev/null
kubectl config --kubeconfig="$OBS_CONFIG" use-context observer >/dev/null
chmod 0600 "$OBS_CONFIG"

cleanup() { rm -f "$OBS_CONFIG" /tmp/go-dns-ca.crt; }
trap cleanup EXIT

kubectl --kubeconfig="$OBS_CONFIG" -n golden-demo logs pod/dns-good -c probe > "$ROOT/observer-dns-good.log"
kubectl --kubeconfig="$OBS_CONFIG" -n golden-demo logs pod/dns-bad -c probe > "$ROOT/observer-dns-bad.log"

go build -o /tmp/sre-agent-dns ./cmd/sre-agent
/tmp/sre-agent-dns diagnose-dns --probe "$ROOT/observer-dns-good.log" --out "$ROOT/healthy-observation.json"
/tmp/sre-agent-dns diagnose-dns --probe "$ROOT/observer-dns-bad.log" --out "$ROOT/broken-observation.json"

# Hold the admin episode until the log-only observer predictions are frozen.
python3 demo/go-dns/build_episode.py --directory "$ROOT"
/tmp/sre-agent-dns evaluate-dns \
  --episode "$ROOT/episode.json" \
  --healthy "$ROOT/healthy-observation.json" \
  --broken "$ROOT/broken-observation.json" \
  --out "$ROOT/evaluation.json"

python3 - <<'PY'
import base64, hashlib, json, pathlib
d=pathlib.Path('/tmp/go-dns-proof')
e=json.loads((d/'episode.json').read_text())
g=json.loads((d/'healthy-observation.json').read_text())
b=json.loads((d/'broken-observation.json').read_text())
r=json.loads((d/'evaluation.json').read_text())
assert g['classification']=='HEALTHY_NAME_AND_IP',g
assert b['classification']=='DNS_FAILURE_WITH_IP_REACHABLE',b
assert r['verdict']=='MATCHED_ISOLATED_DNS_FAULT',r
assert r['production_causality_verified'] is False,r
for label in ('service','healthy_pod','broken_pod','healthy_probe','broken_probe'):
    src=e[label]
    raw=base64.b64decode(src['raw_response_base64'],validate=True)
    assert hashlib.sha256(raw).hexdigest()==src['response_sha256'],label
for x in (g,b):
    src=x['observed']
    raw=base64.b64decode(src['raw_response_base64'],validate=True)
    assert hashlib.sha256(raw).hexdigest()==src['response_sha256']
for label in ('admin-dns-good.log','admin-dns-bad.log','observer-dns-good.log','observer-dns-bad.log'):
    p=json.loads((d/label).read_text())
    assert p['direct_http_status']==200,label
    assert 1 <= len(p['direct_http_attempts']) <= 8,label
    assert p['direct_http_attempts'][-1] == p['direct_http_status'],label
    assert len(p['direct_http_errors']) == len(p['direct_http_attempts']),label
    if 'bad' in label:
        assert p['dns_ok'] is False and p['name_http_status']==0,label
        assert 'nameserver 127.0.0.1' in p['resolver'],label
    else:
        assert p['dns_ok'] is True and p['name_http_status']==200,label
print('PASS: real isolated DNS failure, healthy FQDN control and direct-IP HTTP 200 both paths')
PY

# Adversarial negative inputs must fail closed with exit 3 and NO output.
python3 - <<'PY'
import base64, hashlib, json, pathlib
d=pathlib.Path('/tmp/go-dns-proof')
good=json.loads((d/'healthy-observation.json').read_text())
bad=json.loads((d/'broken-observation.json').read_text())
episode=json.loads((d/'episode.json').read_text())
fake=dict(bad);fake['classification']='DNS_ROOT_CAUSE_CONFIRMED'
(d/'forged-class.json').write_text(json.dumps(fake))
fake=dict(bad);fake['service_ip']='10.1.2.3'
(d/'forged-target.json').write_text(json.dumps(fake))
fake=dict(episode);fake['broken_pod']=dict(episode['broken_pod'])
raw=base64.b64decode(fake['broken_pod']['raw_response_base64'])
pod=json.loads(raw)
pod['spec']['dnsConfig']['nameservers']=['8.8.8.8']
raw=json.dumps(pod,sort_keys=True).encode()
fake['broken_pod']={
  'response_sha256':hashlib.sha256(raw).hexdigest(),
  'raw_response_base64':base64.b64encode(raw).decode(),
}
(d/'forged-admin-policy.json').write_text(json.dumps(fake))
fake=dict(episode);fake['broken_probe']=dict(episode['broken_probe'])
probe=json.loads(base64.b64decode(fake['broken_probe']['raw_response_base64']))
probe['direct_http_status']=0
raw=json.dumps(probe,sort_keys=True).encode()
fake['broken_probe']={
  'response_sha256':hashlib.sha256(raw).hexdigest(),
  'raw_response_base64':base64.b64encode(raw).decode(),
}
(d/'forged-contradiction.json').write_text(json.dumps(fake))
PY
for variant in class target admin-policy contradiction; do
 EP="$ROOT/episode.json"; BROKEN="$ROOT/broken-observation.json"
 case "$variant" in
   class) BROKEN="$ROOT/forged-class.json" ;;
   target) BROKEN="$ROOT/forged-target.json" ;;
   admin-policy) EP="$ROOT/forged-admin-policy.json" ;;
   contradiction) EP="$ROOT/forged-contradiction.json" ;;
 esac
 set +e
 /tmp/sre-agent-dns evaluate-dns --episode "$EP" \
   --healthy "$ROOT/healthy-observation.json" --broken "$BROKEN" \
   --out "$ROOT/forged-$variant-result.json" > "$ROOT/forged-$variant.log" 2>&1
 rc=$?
 set -e
 test "$rc" -eq 3
 test ! -f "$ROOT/forged-$variant-result.json"
 grep -q 'UNKNOWN' "$ROOT/forged-$variant.log"
 echo "PASS: refused forged DNS $variant evidence"
done
echo "PASS: DNS isolation tested without SRE observer writes or incident auto-remediation"
