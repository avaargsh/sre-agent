# Pod container diagnosis — development slice

The existing Evidence v1 observer records Pod phase, which cannot distinguish a Running Pod with a CrashLoopBackOff container. Do not change v1 producer/verifier fields independently: the offline verifier reserves an exact schema.

`internal/poddiagnosis.Assess(expected Target, snapshot Snapshot) Report` consumes a normalized snapshot and separately selected namespace/name/UID. ResourceVersion must be present; every declared regular container must have exactly one status. Unknown states, missing or mismatched identity/coverage, negative restart counts and contradictory non-running ready flags cause UNKNOWN with no findings. Recognized waiting reasons and current OOMKilled are current signals; last termination OOMKilled is historical, not proof of ongoing failure. No recognized signal means UNKNOWN, not HEALTHY. Every report retains false RCA/recovery flags.

The pure classifier now also has `AssessNative(expected Target, raw []byte) (NativeReport, error)`. It validates bounded original Pod v1 JSON using existing `sourcejson.Validate`, enforces exact consumed keys and state unions, requires regular container coverage and separately expected namespace/name/UID, and binds the exact response bytes with SHA-256 and ResourceVersion. Valid inputs may return UNKNOWN when no failure signal is recognized; invalid inputs return an error and no receipt. This is offline replay; freshness and source provenance remain unverified. Init and ephemeral containers, probes, generic exit codes and Events are outside the current slice.

Alternatives: extending the existing v1 projection would break its strict replay contract; a separate normalized classifier is the small independently testable step before a versioned source adapter and offline replay.

The Go `observe.CollectPod(ctx, PodConfig)` library entrypoint now performs a bounded single named Pod GET through the existing source transport (no redirects, fixed scope, deadline and response-size cap). It takes an independently selected target UID, returns the original response body and replayable NativeReport, and returns ErrUnknown with no artifact on HTTP or validation failure. Existing Evidence v1 collection retains the typed decoder over the shared raw read helper. Raw Pod configuration may contain sensitive data; do not publish it to public artifacts or model inputs without review. No proof of freshness, authenticated provenance, Deployment ownership, durable publication or RCA.

Next acceptance: CLI capture/replay, least-privilege named Pod access in disposable kind, real CrashLoopBackOff and healthy negative controls, freshness and cross-source identity binding. No model or Kubernetes writes. Full repository CI and independent review remain required.

## CLI capture and pinned replay

`capture-pod --kube-api URL --namespace NS --pod NAME --uid UID` writes validated original response bytes to stdout. The current CLI expects an operator-controlled authenticated proxy (e.g. local kubectl proxy in a disposable test environment); it does not accept bearer credentials or custom CA flags. Set a private output directory, use umask 077 and shell noclobber when redirecting sensitive raw bytes. Stdout redirection is not atomic artifact publication; on nonzero exit discard the partial file. Do not expose the proxy publicly.

`replay-pod --namespace NS --pod NAME --uid UID --sha256 PIN < pod.json` consumes bounded stdin and returns a structured NativeReport only after the independent expected digest and UID match. PIN and UID must originate from a separately trusted record; hashing the untrusted input immediately before replay is only a lab consistency demonstration, not source attestation. Exit 0 means a valid capture or report, not health or RCA confirmation; 1 output failure, 2 invalid arguments, 3 source rejected. No verified recovery, freshness, authorization, durable journal or production readiness claim.

## Disposable kind acceptance gate (implementation, execution pending)

The dedicated `go-pod-kind` workflow creates a disposable `sre-pod-diagnosis` cluster and runs `demo/go-observe/pod-kind.sh` at the checked-out workflow SHA. The admin fixture injector independently waits for a Ready healthy Pod and a CrashLoopBackOff Pod and obtains their UIDs. A separate short-lived actual ServiceAccount token is used by a loopback kubectl proxy; its Role grants only get on the two named Pods. RBAC checks and denied HTTP GETs are required, along with capture/replay for both Pods, wrong UID and changed raw digest rejection. No raw Pod snapshots or credentials are uploaded; temporary private files are removed. The SHA computed from the captured file is a lab consistency pin only, not independent production source attestation. Expected healthy result remains UNKNOWN without findings. No automatic remediation or recovery certification.

For manual use only in the disposable test environment with kind, Docker, kubectl, Go and Python installed: create a fresh kind cluster named `sre-pod-diagnosis`, check out the candidate, then run `EXPECTED_SHA="$(git rev-parse HEAD)" bash demo/go-observe/pod-kind.sh`. The script refuses a different current context or a missing expected kind cluster and refuses to reuse an existing lab namespace. The CI job runs focused race tests first. This is not proof of a successful execution until actual workflow run/job records and logs for the checked SHA are available.

## Independent receipt verification CLI

After capture and replay, a separate verifier can check the submitted JSON report without contacting Kubernetes:

```sh
sre-agent verify-pod-report --namespace "$NS" --pod "$POD" --uid "$EXPECTED_UID" \
  --sha256 "$INDEPENDENT_SNAPSHOT_SHA256" --report "$REPORT_FILE" < "$RAW_POD_FILE"
```

The expected UID and digest must come from a separate trusted record; do not derive them from the claim. Exit 0 and `STRUCTURALLY_LINKED` mean structural/content consistency only. Invalid data yields exit 3 with no stdout; malformed CLI arguments yield 2. The report file must be operator-owned and trusted; stdin is an explicitly supplied finite stream. **Merge dependency:** land #57 shared boundedAlertFile regular-file/no-follow/nonblocking hardening first, rebase and test #60 on the resulting main, including FIFO/symlink rejection for the report path. Until then the existing named-file helper is byte-bounded but can follow symlinks or block on special files. Do not treat this branch as ready for hostile file paths. No source authentication, freshness, RCA, recovery or execution authority.

## Scoped Pod Events (library development slice)

`observe.CollectPodEvents(ctx, PodConfig)` reads core/v1 events using `involvedObject.uid` and limit 128. `poddiagnosis.AssessEvents` replays exact bytes, requiring EventList resourceVersion and no continuation token, exact Pod namespace/name/UID and core/v1 Pod reference on every item, distinct event UIDs, and bounded reason codes. Empty lists are valid but do not establish health; event messages are omitted from the projection. The original response may contain sensitive material. No source authentication, freshness, or causal assertion. The client selector is not an RBAC boundary: Kubernetes event list permission is namespace-wide. The existing named-Pod-only role is unchanged; use a separately approved reader in a disposable namespace to test events. CLI and live kind event acceptance are not yet implemented. No Evidence v1 wire changes.
