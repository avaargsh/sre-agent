# Pod container diagnosis — development slice

The existing Evidence v1 observer records Pod phase, which cannot distinguish a Running Pod with a CrashLoopBackOff container. Do not change v1 producer/verifier fields independently: the offline verifier reserves an exact schema.

`internal/poddiagnosis.Assess(expected Target, snapshot Snapshot) Report` consumes a normalized snapshot and separately selected namespace/name/UID. ResourceVersion must be present; every declared regular container must have exactly one status. Unknown states, missing or mismatched identity/coverage, negative restart counts and contradictory non-running ready flags cause UNKNOWN with no findings. Recognized waiting reasons and current OOMKilled are current signals; last termination OOMKilled is historical, not proof of ongoing failure. No recognized signal means UNKNOWN, not HEALTHY. Every report retains false RCA/recovery flags.

This is a pure classifier, not a live collector, CLI or source-attested evidence. The caller must normalize exact native state unions, validate original JSON using existing sourcejson.Validate, verify the expected UID, freshness and source provenance, and bind the raw response digest. Init and ephemeral containers, probes, generic exit codes and Events are outside the current slice.

Alternatives: extending the existing v1 projection would break its strict replay contract; a separate normalized classifier is the small independently testable step before a versioned source adapter and offline replay.

Next acceptance: one bounded scoped Pod GET using existing read-only transport, preserve original response bytes/digest and separately pinned UID, reject ambiguous state union or stale/partial sources, add fixture replay and disposable-kind CrashLoopBackOff/healthy negative controls. No model or Kubernetes writes. Full repository CI and independent review remain required.
