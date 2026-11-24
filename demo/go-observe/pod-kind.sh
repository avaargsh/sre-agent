#!/usr/bin/env bash
set -euo pipefail
umask 077
context=kind-sre-pod-diagnosis
ns=sre-pod-lab
: "${EXPECTED_SHA:?expected checkout SHA required}"
test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
test "$(kubectl config current-context)" = "$context"
kind get clusters | grep -Fxq sre-pod-diagnosis
work=$(mktemp -d)
proxy_pid=
created=0
k() { kubectl --context "$context" "$@"; }
cleanup() {
  if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; wait "$proxy_pid" 2>/dev/null || true; fi
  if [[ "$created" = 1 ]]; then k delete namespace "$ns" --wait=false >/dev/null 2>&1 || true; fi
  rm -rf -- "$work"
}
trap cleanup EXIT
k create namespace "$ns"
created=1
k -n "$ns" create -f demo/go-observe/pod-fixtures.yaml
k -n "$ns" wait --for=condition=Ready pod/healthy --timeout=180s
for i in $(seq 1 90); do
  reason=$(k -n "$ns" get pod crash -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}')
  if [[ "$reason" = CrashLoopBackOff ]]; then break; fi
  sleep 2
done
test "$reason" = CrashLoopBackOff
# The admin injects faults and independently obtains the expected UIDs.
crash_uid=$(k -n "$ns" get pod crash -o jsonpath='{.metadata.uid}')
healthy_uid=$(k -n "$ns" get pod healthy -o jsonpath='{.metadata.uid}')
test -n "$crash_uid"; test -n "$healthy_uid"; test "$crash_uid" != "$healthy_uid"
k -n "$ns" create token pod-reader --duration=10m > "$work/token"
k config view --raw --minify --flatten -o json > "$work/admin.json"
python3 - "$work" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
cluster = json.loads((p/'admin.json').read_text())['clusters'][0]['cluster']
assert cluster.get('certificate-authority-data') and not cluster.get('insecure-skip-tls-verify')
config = {'apiVersion':'v1','kind':'Config','clusters':[{'name':'lab','cluster':cluster}],
          'users':[{'name':'reader','user':{'token':(p/'token').read_text().strip()}}],
          'contexts':[{'name':'lab','context':{'cluster':'lab','user':'reader','namespace':'sre-pod-lab'}}],
          'current-context':'lab'}
(p/'reader.json').write_text(json.dumps(config))
PY
rm "$work/admin.json" "$work/token"
r() { kubectl --kubeconfig "$work/reader.json" "$@"; }
# Check the actual reader credential, not only an admin impersonation result.
test "$(r auth can-i get pod/crash -n "$ns")" = yes
test "$(r auth can-i get pod/healthy -n "$ns")" = yes
for check in 'list pods' 'get pod/other' 'get secrets' 'patch pod/crash' 'delete pod/crash'; do
  read -r verb resource <<< "$check"
  test "$(r auth can-i "$verb" "$resource" -n "$ns" || true)" = no
done
test "$(r auth can-i get pod/crash --subresource=log -n "$ns" || true)" = no
test "$(r auth can-i get pod/crash -n default || true)" = no
r proxy --address=127.0.0.1 --port=18081 > "$work/proxy.log" 2>&1 &
proxy_pid=$!
api=http://127.0.0.1:18081
for i in $(seq 1 30); do
  kill -0 "$proxy_pid"
  if curl --max-time 2 -fsS "$api/api/v1/namespaces/$ns/pods/healthy" >/dev/null; then break; fi
  sleep 1
done
kill -0 "$proxy_pid"
curl --max-time 2 -fsS "$api/api/v1/namespaces/$ns/pods/healthy" >/dev/null
# Real denied GET through the restricted proxy; no mutation attempted.
for path in "/api/v1/namespaces/$ns/pods" "/api/v1/namespaces/$ns/pods/other" "/api/v1/namespaces/$ns/secrets" "/api/v1/namespaces/default/pods/crash"; do
  test "$(curl --max-time 5 -sS -o /dev/null -w '%{http_code}' "$api$path")" = 403
done
go build -o "$work/sre-agent" ./cmd/sre-agent
for pod in crash healthy; do
  uid=$crash_uid
  if [[ "$pod" = healthy ]]; then uid=$healthy_uid; fi
  # Wait for a real waiting state; status can transition during backoff.
  captured=0
  for i in $(seq 1 30); do
    if "$work/sre-agent" capture-pod --kube-api "$api" --namespace "$ns" --pod "$pod" --uid "$uid" > "$work/$pod.raw"; then
      pin=$(sha256sum "$work/$pod.raw" | cut -d' ' -f1)
      "$work/sre-agent" replay-pod --namespace "$ns" --pod "$pod" --uid "$uid" --sha256 "$pin" < "$work/$pod.raw" > "$work/$pod.report"
      if python3 - "$work/$pod.report" "$pod" "$pin" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); a = r['assessment']
assert r['raw_sha256'] == sys.argv[3]
assert r['source_authenticated'] is False and a['root_cause_verified'] is False and a['recovery_verified'] is False
if sys.argv[2] == 'crash':
    assert a['status'] == 'SIGNALS_PRESENT' and any(f['code']=='CrashLoopBackOff' and f['temporal_scope']=='current' for f in a['findings'])
else:
    assert a['status'] == 'UNKNOWN' and not a['findings']
PY
      then captured=1; break; fi
    fi
    sleep 2
  done
  test "$captured" = 1
  test "$("$work/sre-agent" verify-pod-report --namespace "$ns" --pod "$pod" --uid "$uid" --sha256 "$pin" --report "$work/$pod.report" < "$work/$pod.raw")" = STRUCTURALLY_LINKED
  echo "PASS $pod capture, replay and independent report verification"
done
reject() { local rc=0; "$@" > "$work/rejected" 2> "$work/rejected.err" || rc=$?; test "$rc" = 3; test ! -s "$work/rejected"; }
reject "$work/sre-agent" capture-pod --kube-api "$api" --namespace "$ns" --pod healthy --uid "$crash_uid"
pin=$(sha256sum "$work/crash.raw" | cut -d' ' -f1)
cp "$work/crash.raw" "$work/tampered.raw"
printf ' ' >> "$work/tampered.raw"
reject "$work/sre-agent" replay-pod --namespace "$ns" --pod crash --uid "$crash_uid" --sha256 "$pin" < "$work/tampered.raw"
echo "PASS wrong UID and tampered raw rejection; no RCA or recovery proof"
# Acceptance requires #57's safe boundedAlertFile implementation.
# Use an independently selected UID and the original pinned raw bytes.
python3 - "$work/crash.report" "$work/forged.report" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text())
report["source_authenticated"] = True
pathlib.Path(sys.argv[2]).write_text(json.dumps(report))
PY
verify_crash() {
  timeout 5s "$work/sre-agent" verify-pod-report --namespace "$ns" --pod crash --uid "$crash_uid" --sha256 "$pin" --report "$1" < "$work/crash.raw"
}
reject verify_crash "$work/forged.report"
ln -s "$work/crash.report" "$work/aliased.report"
mkfifo "$work/blocked.report"
reject verify_crash "$work/aliased.report"
reject verify_crash "$work/blocked.report"
echo "PASS forged receipt, symlink and FIFO rejection; timeout is a failure"
