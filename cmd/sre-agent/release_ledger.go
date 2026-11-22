package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "io"

 "github.com/avaargsh/sre-agent/internal/releaseledger"
)

// recordReleaseLab is the ONLY CLI writer of the local admission journal.
// It repeats the complete G2l authorized v2 proof check on each call; there
// is no bypass path via a client-supplied "verified=true" assertion.
// It records LAB admission, not any real production deploy, publication or
// release authorization. Ledger input must live outside evidence source root.
func recordReleaseLab(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("record-release-lab",flag.ContinueOnError)
 f.SetOutput(stderr)
 enabled:=f.Bool("lab-only",false,"acknowledge single-host experimental ledger, NOT production release")
 ledger:=f.String("ledger-dir","","existing private local 0700 ledger directory outside evidence root")
 tenant:=f.String("tenant","","lab tenant label, not authenticated production identity")
 project:=f.String("project","","lab project label")
 release:=f.String("release-id","","single-use logical release slot")
 root:=f.String("root","","original raw evidence directory")
 attestation:=f.String("attestation","","signed original evidence v2 envelope")
 pub:=f.String("trusted-public-key","","independent signer PEM")
 policy:=f.String("policy-file","","independently approved signer policy")
 policySHA:=f.String("trusted-policy-sha256","","externally approved exact SHA256 of policy file")
 repo:=f.String("expected-repo","","independently expected repository")
 head:=f.String("expected-head","","independent exact commit SHA")
 run:=f.String("expected-run-id","","independent CI run identifier")
 attempt:=f.String("expected-run-attempt","","independent CI run attempt")
 episode:=f.String("expected-episode","","independent episode")
 keyID:=f.String("expected-signing-key-id","","independently pinned signer key SPKI SHA256")
 version:=f.String("expected-signing-key-version","","independently approved key version")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||!*enabled||*ledger==""||*root==""||*attestation==""{
  fmt.Fprintln(stderr,"UNKNOWN: explicit lab-only acknowledgement, ledger, evidence, and authorization required")
  return 3
 }
 // An untrusted bundle must never house the ledger that tracks its own use.
 inside,err:=publicKeyInEvidenceRoot(*root,*ledger)
 if err!=nil||inside{
  fmt.Fprintln(stderr,"UNKNOWN: ledger must exist OUTSIDE evidence root")
  return 3
 }
 before,err:=readSmallFile(*attestation,128<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: cannot read attestation before verification:",err);return 3}
 expectedSHA:=sha256.Sum256(before)
 authArgs:=[]string{
  "--root",*root,"--attestation",*attestation,
  "--trusted-public-key",*pub,
  "--policy-file",*policy,"--trusted-policy-sha256",*policySHA,
  "--expected-repo",*repo,"--expected-head",*head,
  "--expected-run-id",*run,"--expected-run-attempt",*attempt,
  "--expected-episode",*episode,
  "--expected-signing-key-id",*keyID,"--expected-signing-key-version",*version,
 }
 if rc:=verifyEvidenceAuthorized(authArgs,io.Discard,stderr);rc!=0{
  fmt.Fprintln(stderr,"UNKNOWN: no lab admission: external authorization and original source verification failed")
  return 3
 }
 after,err:=readSmallFile(*attestation,128<<10)
 if err!=nil||sha256.Sum256(after)!=expectedSHA{
  fmt.Fprintln(stderr,"UNKNOWN: original attestation changed during verification")
  return 3
 }
 req:=releaseledger.Request{
  Tenant:*tenant,Project:*project,ReleaseID:*release,
  EvidenceSHA256:hex.EncodeToString(expectedSHA[:]),
  PolicySHA256:*policySHA,
  Repository:*repo,CommitSHA:*head,
  WorkflowRun:*run,WorkflowAttempt:*attempt,Episode:*episode,
  SigningKeyID:*keyID,SigningKeyVersion:*version,
 }
 receipt,err:=releaseledger.Commit(*ledger,req)
 if err!=nil{
  fmt.Fprintln(stderr,"UNKNOWN: no new admission receipt; replay/lock/corruption:",err)
  return 3
 }
 if err:=json.NewEncoder(stdout).Encode(receipt);err!=nil{
  // The entry may already be durable. Never auto-retry a lost ACK.
  fmt.Fprintln(stderr,"UNKNOWN: receipt may have committed; reconcile journal before any retry:",err)
  return 3
 }
 return 0
}

// readReleaseLab never repairs or silently normalizes an interrupted ledger.
func readReleaseLab(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("read-release-lab",flag.ContinueOnError);f.SetOutput(stderr)
 root:=f.String("ledger-dir","","private local ledger directory")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*root==""{fmt.Fprintln(stderr,"ledger-dir required");return 2}
 receipts,err:=releaseledger.Read(*root)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: cannot replay immutable lab receipts:",err);return 3}
 if err:=json.NewEncoder(stdout).Encode(receipts);err!=nil{return 1}
 return 0
}
