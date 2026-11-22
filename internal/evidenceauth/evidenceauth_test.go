package evidenceauth

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func signedFixture(t *testing.T)(string,Expected,[]byte,ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,"before-service.json"),[]byte(`{"kind":"Service","metadata":{"uid":"svc-1"}}`),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,"during-probe.json"),[]byte(`{"http":0,"dns_ok":true}`),0600);err!=nil{t.Fatal(err)}
 expected:=Expected{Repository:"avaargsh/sre-agent",Commit:"b0228fafedfa577ed05b771e6c8ec3536982e6e5",WorkflowRun:"44995351332",Episode:"np-calico-egress-001"}
 manifest,err:=Build(root,[]string{"during-probe.json","before-service.json"},expected)
 if err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 envelope,err:=Sign(manifest,priv)
 if err!=nil{t.Fatal(err)}
 return root,expected,envelope,pub,priv
}
func TestTrustAnchorAndCompleteSignedEvidenceIndex(t *testing.T){
 root,expected,envelope,pub,_:=signedFixture(t)
 got,err:=Verify(root,envelope,pub,expected)
 if err!=nil{t.Fatal(err)}
 if got.SchemaVersion!="sre.evidence-manifest/v1"||len(got.Files)!=2||
  got.Files[0].Path!="before-service.json"||got.Files[1].Path!="during-probe.json"{
  t.Fatalf("incorrect manifest canonical order or completeness: %+v",got)
 }
}
func TestRejectWrongKeyOrUnpinnedIdentity(t *testing.T){
 root,expected,envelope,pub,_:=signedFixture(t)
 other,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err:=Verify(root,envelope,other,expected);err==nil{t.Fatal("accepted unrelated public key")}
 wrong:=expected
 wrong.Commit=strings.Repeat("a",40)
 if _,err:=Verify(root,envelope,pub,wrong);err==nil{t.Fatal("accepted unsigned external commit expectation")}
 wrong=expected;wrong.Repository="attacker/sre-agent"
 if _,err:=Verify(root,envelope,pub,wrong);err==nil{t.Fatal("accepted wrong repo")}
 wrong=expected;wrong.WorkflowRun="44999999999"
 if _,err:=Verify(root,envelope,pub,wrong);err==nil{t.Fatal("accepted wrong workflow run")}
 wrong=expected;wrong.Episode="other-episode"
 if _,err:=Verify(root,envelope,pub,wrong);err==nil{t.Fatal("accepted wrong episode")}
}
func TestRejectCorruptedFilesSignatureAndReplayedManifest(t *testing.T){
 root,expected,envelope,pub,_:=signedFixture(t)
 if err:=os.WriteFile(filepath.Join(root,"during-probe.json"),[]byte(`{"http":200,"dns_ok":true}`),0600);err!=nil{t.Fatal(err)}
 if _,err:=Verify(root,envelope,pub,expected);err==nil{t.Fatal("accepted tampered original file with unchanged signed digest")}
 if err:=os.Remove(filepath.Join(root,"before-service.json"));err!=nil{t.Fatal(err)}
 if _,err:=Verify(root,envelope,pub,expected);err==nil{t.Fatal("accepted missing original file")}
 root,expected,envelope,pub,_=signedFixture(t)
 var a Envelope
 if err:=json.Unmarshal(envelope,&a);err!=nil{t.Fatal(err)}
 a.SignatureBase64=base64.StdEncoding.EncodeToString(make([]byte,ed25519.SignatureSize))
 forged,_:=json.Marshal(a)
 if _,err:=Verify(root,forged,pub,expected);err==nil{t.Fatal("accepted fake signature")}
}
func TestRejectDuplicateJSONKeysEvenWhenAttackerCanSign(t *testing.T){
 root,expected,envelope,pub,priv:=signedFixture(t)
 dupEnvelope:=strings.Replace(string(envelope),`"schema_version":"sre.evidence-attestation/v1"`,
  `"schema_version":"sre.evidence-attestation/v1","schema_version":"sre.evidence-attestation/v1"`,1)
 if dupEnvelope==string(envelope){t.Fatal("fixture envelope JSON changed")}
 if _,err:=Verify(root,[]byte(dupEnvelope),pub,expected);err==nil{t.Fatal("accepted duplicate envelope key")}
 var a Envelope
 if err:=json.Unmarshal(envelope,&a);err!=nil{t.Fatal(err)}
 manifest,err:=base64.StdEncoding.DecodeString(a.PayloadBase64);if err!=nil{t.Fatal(err)}
 dup:=strings.Replace(string(manifest),`"repository":"avaargsh/sre-agent"`,
  `"repository":"avaargsh/sre-agent","repository":"avaargsh/sre-agent"`,1)
 if dup==string(manifest){t.Fatal("fixture manifest JSON changed")}
 if _,err:=Sign([]byte(dup),priv);err==nil{t.Fatal("signer accepted ambiguous manifest")}
 raw:=[]byte(dup)
 a.PayloadBase64=base64.StdEncoding.EncodeToString(raw)
 a.SignatureBase64=base64.StdEncoding.EncodeToString(ed25519.Sign(priv,append([]byte(DomainSeparator),raw...)))
 forged,_:=json.Marshal(a)
 if _,err:=Verify(root,forged,pub,expected);err==nil{t.Fatal("verifier accepted valid signature on duplicate-key manifest")}
}
func TestRejectPathTraversalSymlinksAndNonLocalInputs(t *testing.T){
 root,expected,_,_,_:=signedFixture(t)
 for _,p:=range []string{"../escape","/tmp/other","foo/../../a","./before-service.json","before-service.json/..",""}{
  if _,err:=Build(root,[]string{p},expected);err==nil{t.Fatalf("allowed nonlocal path %q",p)}
 }
 if err:=os.Symlink(filepath.Join(root,"before-service.json"),filepath.Join(root,"linked.json"));err!=nil{t.Fatal(err)}
 if _,err:=Build(root,[]string{"linked.json"},expected);err==nil{t.Fatal("accepted symlink source")}
}
func TestRejectMissingTrustContextAndDuplicatePaths(t *testing.T){
 root,expected,_,_,_:=signedFixture(t)
 if _,err:=Build(root,[]string{"before-service.json","before-service.json"},expected);err==nil{t.Fatal("accepted duplicate path")}
 missing:=expected;missing.WorkflowRun=""
 if _,err:=Build(root,[]string{"before-service.json"},missing);err==nil{t.Fatal("accepted incomplete external run binding")}
 missing=expected;missing.Commit="main"
 if _,err:=Build(root,[]string{"before-service.json"},missing);err==nil{t.Fatal("accepted mutable branch instead of SHA")}
}
