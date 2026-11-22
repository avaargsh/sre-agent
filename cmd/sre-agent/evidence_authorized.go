package main

import (
 "flag"
 "fmt"
 "io"
 "os"
 "time"

 "github.com/avaargsh/sre-agent/internal/evidenceauth"
)

// verifyEvidenceAuthorized is deliberately a distinct command from the
// G2j/G2k signature-only verifier. A cryptographically valid signature does
// NOT authorize a release. Policy bytes and their trusted digest MUST be
// obtained from outside the evidence artifact.
func verifyEvidenceAuthorized(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("verify-evidence-authorized",flag.ContinueOnError)
 f.SetOutput(stderr)
 root:=f.String("root","","directory containing original evidence bytes")
 attestation:=f.String("attestation","","signed v2 envelope")
 pub:=f.String("trusted-public-key","","externally authorized signer public PEM")
 policyFile:=f.String("policy-file","","external, digest-pinned key authorization policy")
 policySHA:=f.String("trusted-policy-sha256","","out-of-band SHA256 of policy-file bytes")
 repo:=f.String("expected-repo","","independently expected repository")
 head:=f.String("expected-head","","independently expected immutable commit SHA")
 run:=f.String("expected-run-id","","independently expected CI run ID")
 attempt:=f.String("expected-run-attempt","","independently expected run attempt")
 episode:=f.String("expected-episode","","independently expected episode")
 keyID:=f.String("expected-signing-key-id","","externally pinned signing key fingerprint")
 version:=f.String("expected-signing-key-version","","externally approved signing key version")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*root==""||*attestation==""||*pub==""||
  *policyFile==""||*policySHA==""{
  fmt.Fprintln(stderr,"UNKNOWN: external evidence, policy, expected digest and trust key are mandatory")
  return 3
 }
 for _,candidate:=range []string{*pub,*policyFile}{
  inside,err:=publicKeyInEvidenceRoot(*root,candidate)
  if err!=nil||inside{
   fmt.Fprintln(stderr,"UNKNOWN: trust policy and key must be real files OUTSIDE evidence root")
   return 3
  }
  info,err:=os.Lstat(candidate)
  if err!=nil||!info.Mode().IsRegular()||info.Size()==0||info.Size()>64<<10{
   fmt.Fprintln(stderr,"UNKNOWN: external trust file invalid or too large")
   return 3
  }
 }
 key,err:=readTrustedPublicKey(*pub)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: no valid externally trusted signer key:",err);return 3}
 expected:=fixedIdentity(*repo,*head,*run,*attempt,*episode,*keyID,*version)
 policyRaw,err:=readSmallFile(*policyFile,64<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: no trust policy source:",err);return 3}
 // Uses verifier host's wall clock; production must separately establish
 // trusted wall-clock and policy-signature / policy-revision freshness.
 if err:=evidenceauth.AuthorizeSigner(policyRaw,*policySHA,key,expected,time.Now().UTC());err!=nil{
  fmt.Fprintln(stderr,"UNKNOWN: signer not authorized under pinned external policy:",err)
  return 3
 }
 envelope,err:=readSmallFile(*attestation,128<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: signed evidence missing:",err);return 3}
 manifest,err:=evidenceauth.Verify(*root,envelope,key,expected)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid signed original evidence:",err);return 3}
 fmt.Fprintf(stdout,"PASS: verified signature + %d source digests + external digest-pinned signer policy; NOT proof of production signer identity without authorized policy publication\n",len(manifest.Files))
 return 0
}
