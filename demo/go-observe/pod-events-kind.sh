#!/usr/bin/env bash
set -euo pipefail
umask 077
context=kind-sre-pod-diagnosis
ns=sre-events-lab
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
k -n "$ns" create -f demo/go-observe/pod-events-fixtures.yaml
uid=$(k -n "$ns" get pod crash -o jsonpath='{.metadata.uid}')
test -n "$uid"
# Require a real kubelet BackOff event, not a fabricated EventList.
found=0
for i in $(seq 1 90); do
  if k -n "$ns" get events --field-selector "involvedObject.uid=$uid,reason=BackOff" -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}' | grep -Fxq BackOff; then found=1; break; fi
  sleep 2
done
test "$found" = 1
event_name=$(k -n "$ns" get events --field-selector "involvedObject.uid=$uid,reason=BackOff" -o jsonpath='{.items[0].metadata.name}')
test -n "$event_name"
k -n "$ns" create token events-reader --duration=10m > "$work/token"
k config view --raw --minify --flatten -o json | python3 -c '
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
cluster = json.load(sys.stdin)["clusters"][0]["cluster"]
assert cluster.get("certificate-authority-data") and not cluster.get("insecure-skip-tls-verify")
config = {"apiVersion":"v1","kind":"Config","clusters":[{"name":"lab","cluster":cluster}],
          "users":[{"name":"reader","user":{"token":(p/"token").read_text().strip()}}],
          "contexts":[{"name":"lab","context":{"cluster":"lab","user":"reader","namespace":"sre-events-lab"}}],
          "current-context":"lab"}
(p/"reader.json").write_text(json.dumps(config))
' "$work"
rm "$work/token"
r() { kubectl --kubeconfig "$work/reader.json" "$@"; }
# List authorization is namespace-wide. No Pod/Secret reads or writes granted.
test "$(r auth can-i list events -n "$ns")" = yes
for check in 'get events' 'get pod/crash' 'list pods' 'list secrets' 'create events' 'patch events' 'delete events'; do
  read -r verb resource <<< "$check"
  test "$(r auth can-i "$verb" "$resource" -n "$ns" || true)" = no
done
test "$(r auth can-i list events -n default || true)" = no
r proxy --address=127.0.0.1 --port=18082 > "$work/proxy.log" 2>&1 &
proxy_pid=$!
api=http://127.0.0.1:18082
for i in $(seq 1 30); do
  kill -0 "$proxy_pid"
  if curl --max-time 2 -fsS "$api/api/v1/namespaces/$ns/events" >/dev/null; then break; fi
  sleep 1
done
kill -0 "$proxy_pid"
curl --max-time 2 -fsS "$api/api/v1/namespaces/$ns/events" >/dev/null
for path in "/api/v1/namespaces/$ns/pods/crash" "/api/v1/namespaces/$ns/secrets" "/api/v1/namespaces/$ns/events/$event_name" "/api/v1/namespaces/default/events"; do
  test "$(curl --max-time 5 -sS -o /dev/null -w '%{http_code}' "$api$path")" = 403
done
go build -o "$work/sre-agent" ./cmd/sre-agent
"$work/sre-agent" capture-events --kube-api "$api" --namespace "$ns" --pod crash --uid "$uid" > "$work/events.raw"
pin=$(sha256sum "$work/events.raw" | cut -d' ' -f1)
"$work/sre-agent" replay-events --namespace "$ns" --pod crash --uid "$uid" --sha256 "$pin" < "$work/events.raw" > "$work/events.report"
python3 - "$work/events.report" "$uid" "$pin" <<'PY'
import json, pathlib, sys
r = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert r['schema_version'] == 'sre.pod-events/v1'
assert r['target'] == {'Namespace':'sre-events-lab','Name':'crash','UID':sys.argv[2]}
assert r['raw_sha256'] == sys.argv[3] and r['source_authenticated'] is False
assert any(e['type']=='Warning' and e['reason']=='BackOff' for e in r['events'])
assert all(set(e)=={'uid','type','reason'} for e in r['events'])
PY
verify() {
  timeout 5s "$work/sre-agent" verify-events-report --namespace "$ns" --pod crash --uid "$uid" --sha256 "$pin" --report "$1" < "$work/events.raw"
}
test "$(verify "$work/events.report")" = STRUCTURALLY_LINKED
reject() { local rc=0; "$@" > "$work/rejected" 2> "$work/rejected.err" || rc=$?; test "$rc" = 3; test ! -s "$work/rejected"; }
python3 - "$work/events.report" "$work/forged.report" <<'PY'
import json, pathlib, sys
r = json.loads(pathlib.Path(sys.argv[1]).read_text()); r['source_authenticated'] = True
pathlib.Path(sys.argv[2]).write_text(json.dumps(r))
PY
reject verify "$work/forged.report"
ln -s "$work/events.report" "$work/alias.report"
mkfifo "$work/blocked.report"
reject verify "$work/alias.report"
reject verify "$work/blocked.report"
reject "$work/sre-agent" replay-events --namespace "$ns" --pod crash --uid replacement --sha256 "$pin" < "$work/events.raw"
printf ' ' >> "$work/events.raw"
reject "$work/sre-agent" replay-events --namespace "$ns" --pod crash --uid "$uid" --sha256 "$pin" < "$work/events.raw"
echo 'PASS real BackOff EventList capture, replay, verification and negative controls; no provenance or RCA proof'
