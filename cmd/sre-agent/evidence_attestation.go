package main

import (
 "crypto/ed25519"
 "crypto/x509"
 "encoding/pem"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"

 "github.com/avaargsh/sre-agent/internal/evidenceauth"
)
func saveExclusive(path string,payload []byte)error{
 if path==""||path=="-"{return fmt.Errorf("explicit new output file required")}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 defer f.Close()
 if _,err:=f.Write(payload);err!=nil{
  f.Close()
  os.Remove(path)
  return err
 }
 return nil
}
func fixedIdentity(repo,commit,run,attempt,episode,keyID,keyVersion string)evidenceauth.Expected{
 return evidenceauth.Expected{Repository:repo,Commit:commit,WorkflowRun:run,WorkflowAttempt:attempt,
  Episode:episode,SigningKeyID:keyID,SigningKeyVersion:keyVersion}
}
func indexEvidence(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("index-evidence",flag.ContinueOnError);f.SetOutput(stderr)
 root:=f.String("root","","local folder with original witness files")
 paths:=f.String("paths","","comma-separated relative explicit witness paths")
 repo:=f.String("repo","","operator-expected repository")
 head:=f.String("head","","operator-expected 40-character commit HEAD SHA")
 run:=f.String("run-id","","operator-expected GitHub workflow run ID")
 attempt:=f.String("run-attempt","","operator-expected GitHub workflow run attempt (starts at 1)")
 episode:=f.String("episode","","operator-expected episode ID")
 keyID:=f.String("signing-key-id","","SHA256 of authorized signer PKIX SPKI DER")
 keyVersion:=f.String("signing-key-version","","externally authorized signer key version label")
 out:=f.String("out","","new exact-byte manifest file")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*root==""||*paths==""||*out==""{fmt.Fprintln(stderr,"missing source root, paths or output");return 2}
 m,err:=evidenceauth.Build(*root,strings.Split(*paths,","),fixedIdentity(*repo,*head,*run,*attempt,*episode,*keyID,*keyVersion))
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: cannot build identity-bound manifest:",err);return 3}
 if err:=saveExclusive(*out,m);err!=nil{fmt.Fprintln(stderr,"cannot save manifest:",err);return 1}
 fmt.Fprintln(stdout,"PASS: bounded original evidence index created")
 return 0
}
func readPrivateKey(path string)(ed25519.PrivateKey,error){
 if path==""{return nil,fmt.Errorf("private key path required")}
 info,err:=os.Lstat(path)
 if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||info.Size()>8192{
  return nil,fmt.Errorf("private key must be a small mode-0600 regular file, not a symlink")
 }
 raw,err:=os.ReadFile(path);if err!=nil{return nil,err}
 block,rest:=pem.Decode(raw)
 if block==nil||block.Type!="PRIVATE KEY"||len(rest)!=0{return nil,fmt.Errorf("invalid PEM private key")}
 value,err:=x509.ParsePKCS8PrivateKey(block.Bytes)
 if err!=nil{return nil,err}
 key,ok:=value.(ed25519.PrivateKey)
 if !ok{return nil,fmt.Errorf("not an Ed25519 private key")}
 return key,nil
}
// A self-issued public key packaged with the attested evidence cannot serve
// as an independently authorized trust anchor. Resolve both paths to avoid
// bypassing the check using a parent-directory symlink.
func publicKeyInEvidenceRoot(root,keyPath string)(bool,error){
 r,err:=filepath.EvalSymlinks(root)
 if err!=nil{return false,err}
 k,err:=filepath.EvalSymlinks(keyPath)
 if err!=nil{return false,err}
 r,err=filepath.Abs(r);if err!=nil{return false,err}
 k,err=filepath.Abs(k);if err!=nil{return false,err}
 rel,err:=filepath.Rel(r,k)
 if err!=nil{return false,err}
 return rel=="."||filepath.IsLocal(rel),nil
}
func readTrustedPublicKey(path string)(ed25519.PublicKey,error){
 if path==""{return nil,fmt.Errorf("explicit trusted public key file required")}
 info,err:=os.Lstat(path)
 if err!=nil||!info.Mode().IsRegular()||info.Size()>8192{return nil,fmt.Errorf("invalid trusted public key file")}
 raw,err:=os.ReadFile(path);if err!=nil{return nil,err}
 block,rest:=pem.Decode(raw)
 if block==nil||block.Type!="PUBLIC KEY"||len(rest)!=0{return nil,fmt.Errorf("bad public-key PEM")}
 key,err:=x509.ParsePKIXPublicKey(block.Bytes);if err!=nil{return nil,err}
 pub,ok:=key.(ed25519.PublicKey)
 if !ok{return nil,fmt.Errorf("expected Ed25519 external trust key")}
 return pub,nil
}
func signEvidence(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("sign-evidence",flag.ContinueOnError);f.SetOutput(stderr)
 manifest:=f.String("manifest","","exact-byte canonical source manifest")
 privateKey:=f.String("private-key","","externally authorized Ed25519 PKCS8 PEM (never commit this)")
 out:=f.String("out","","new signed envelope file")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*manifest==""||*privateKey==""||*out==""{fmt.Fprintln(stderr,"missing signing arguments");return 2}
 m,err:=readSmallFile(*manifest,64<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: cannot read manifest:",err);return 3}
 key,err:=readPrivateKey(*privateKey)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: no authorized signing key:",err);return 3}
 attestation,err:=evidenceauth.Sign(m,key)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: invalid source manifest:",err);return 3}
 if err:=saveExclusive(*out,attestation);err!=nil{fmt.Fprintln(stderr,"cannot save signed envelope:",err);return 1}
 fmt.Fprintln(stdout,"PASS: signed exact manifest bytes; caller owns signer authorization")
 return 0
}
func verifyEvidence(args []string,stdout,stderr io.Writer)int{
 f:=flag.NewFlagSet("verify-evidence",flag.ContinueOnError);f.SetOutput(stderr)
 root:=f.String("root","","local original evidence source directory")
 envelope:=f.String("attestation","","signed envelope JSON")
 pub:=f.String("trusted-public-key","","independently pinned Ed25519 PKIX public-key PEM")
 repo:=f.String("expected-repo","","expected repository from outside attestation")
 head:=f.String("expected-head","","expected exact commit from outside attestation")
 run:=f.String("expected-run-id","","expected workflow run ID from outside attestation")
 attempt:=f.String("expected-run-attempt","","expected exact workflow run attempt from outside attestation")
 episode:=f.String("expected-episode","","expected episode ID from outside attestation")
 keyID:=f.String("expected-signing-key-id","","expected signer public-key SPKI fingerprint from outside attestation")
 keyVersion:=f.String("expected-signing-key-version","","authorized signing key version from outside attestation")
 if err:=f.Parse(args);err!=nil{return 2}
 if len(f.Args())!=0||*root==""||*envelope==""||*pub==""{fmt.Fprintln(stderr,"missing independent verification arguments");return 2}
 inside,err:=publicKeyInEvidenceRoot(*root,*pub)
 if err!=nil||inside{
  fmt.Fprintln(stderr,"UNKNOWN: trusted key must come from outside the evidence root")
  return 3
 }
 raw,err:=readSmallFile(*envelope,128<<10)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: signed envelope unreadable");return 3}
 key,err:=readTrustedPublicKey(*pub)
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: no independently pinned trust anchor:",err);return 3}
 result,err:=evidenceauth.Verify(*root,raw,key,fixedIdentity(*repo,*head,*run,*attempt,*episode,*keyID,*keyVersion))
 if err!=nil{fmt.Fprintln(stderr,"UNKNOWN: evidence signature / identity / source invalid:",err);return 3}
 fmt.Fprintf(stdout,"PASS: signed original evidence verified for %d files (NOT production provenance without authorized trust anchor)\n",len(result.Files))
 return 0
}
