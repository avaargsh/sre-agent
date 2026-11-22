package evidenceauth

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "strings"
 "testing"
 "time"
)

func samplePolicy(t *testing.T) (SignerPolicy, Expected, ed25519.PublicKey, time.Time) {
 t.Helper()
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 expected:=Expected{Repository:"avaargsh/sre-agent",Commit:"13d7ea961e6f5fa3a60322eef3d0d5a64c3b7021",
  WorkflowRun:"44998089192",WorkflowAttempt:"2",Episode:"np-calico-egress-001",
  SigningKeyID:KeyID(pub),SigningKeyVersion:"approved-2026-q4"}
 policy:=SignerPolicy{SchemaVersion:"sre.signer-policy/v1",Revision:"approved-rev-001",
  Grants:[]SignerGrant{{KeyID:expected.SigningKeyID,KeyVersion:expected.SigningKeyVersion,
   Repository:expected.Repository,Episode:expected.Episode,Status:"active",
   NotBefore:"2026-01-01T00:00:00Z",NotAfter:"2027-01-01T00:00:00Z"}}}
 return policy,expected,pub,time.Date(2026,11,22,7,0,0,0,time.UTC)
}
func policyWire(t *testing.T,p SignerPolicy)([]byte,string){
 t.Helper()
 wire,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 return wire,digest(wire)
}
func TestSignerPolicyExternalDigestAndExactScope(t *testing.T){
 p,expected,pub,now:=samplePolicy(t)
 raw,hash:=policyWire(t,p)
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err!=nil{t.Fatal(err)}
}
func TestRejectRevokedExpiredWrongScopeOrKey(t *testing.T){
 cases:=map[string]func(*SignerPolicy){
  "revoked":func(p *SignerPolicy){p.Grants[0].Status="revoked"},
  "suspended":func(p *SignerPolicy){p.Grants[0].Status="suspended"},
  "unknown-status":func(p *SignerPolicy){p.Grants[0].Status="active-but-weak"},
  "expired":func(p *SignerPolicy){p.Grants[0].NotAfter="2026-01-01T00:00:00Z"},
  "not-yet-valid":func(p *SignerPolicy){p.Grants[0].NotBefore="2027-01-01T00:00:00Z"},
  "repo-drift":func(p *SignerPolicy){p.Grants[0].Repository="attacker/sre-agent"},
  "episode-drift":func(p *SignerPolicy){p.Grants[0].Episode="other-incident"},
  "key-version-drift":func(p *SignerPolicy){p.Grants[0].KeyVersion="approved-2026-q3"},
  "key-id-drift":func(p *SignerPolicy){p.Grants[0].KeyID=strings.Repeat("a",64)},
  "bad-time-window":func(p *SignerPolicy){p.Grants[0].NotBefore="2028-01-01T00:00:00Z"},
  "missing-scope":func(p *SignerPolicy){p.Grants[0].Episode=""},
  "legacy-schema":func(p *SignerPolicy){p.SchemaVersion="sre.signer-policy/v0"},
  "missing-revision":func(p *SignerPolicy){p.Revision=""},
 }
 for label,change:=range cases{
  t.Run(label,func(t *testing.T){
   p,expected,pub,now:=samplePolicy(t)
   change(&p)
   raw,hash:=policyWire(t,p)
   if err:=AuthorizeSigner(raw,hash,pub,expected,now);err==nil{
    t.Fatal("unauthorized signing key accepted after independently re-pinning policy")
   }
  })
 }
}
func TestRejectPolicyWrongExternalDigestAndKey(t *testing.T){
 p,expected,pub,now:=samplePolicy(t)
 raw,hash:=policyWire(t,p)
 if err:=AuthorizeSigner(raw,strings.Repeat("0",64),pub,expected,now);err==nil{t.Fatal("accepted different external digest")}
 if err:=AuthorizeSigner(raw,"",pub,expected,now);err==nil{t.Fatal("allowed absent trust anchor digest")}
 other,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if err:=AuthorizeSigner(raw,hash,other,expected,now);err==nil{t.Fatal("accepted unregistered signing public key")}
 expected.SigningKeyVersion="approved-2026-q3"
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err==nil{t.Fatal("accepted unsigned signer version change")}
}
func TestRejectAmbiguousPolicyAndUnknownFields(t *testing.T){
 p,expected,pub,now:=samplePolicy(t)
 p.Grants=append(p.Grants,p.Grants[0])
 raw,hash:=policyWire(t,p)
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err==nil{t.Fatal("accepted duplicated scope grant")}
 p,expected,pub,now=samplePolicy(t)
 raw,_=policyWire(t,p)
 dup:=strings.Replace(string(raw),`"revision":"approved-rev-001"`,`"revision":"approved-rev-001","revision":"approved-rev-001"`,1)
 if dup==string(raw){t.Fatal("duplicate top-level test fixture missing")}
 if err:=AuthorizeSigner([]byte(dup),digest([]byte(dup)),pub,expected,now);err==nil{t.Fatal("accepted duplicate JSON key with matching digest")}
 unknown:=strings.Replace(string(raw),`"status":"active"`,`"status":"active","bypass":true`,1)
 if unknown==string(raw){t.Fatal("unknown field test fixture missing")}
 if err:=AuthorizeSigner([]byte(unknown),digest([]byte(unknown)),pub,expected,now);err==nil{t.Fatal("accepted unknown policy grant field")}
}
func TestRejectPolicyTimeAndUnrelatedKeys(t *testing.T){
 p,expected,pub,now:=samplePolicy(t)
 p.Grants[0].NotBefore="2027-01-01T00:00:00Z"
 p.Grants[0].NotAfter="2026-01-01T00:00:00Z"
 raw,hash:=policyWire(t,p)
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err==nil{t.Fatal("inverted validity window accepted")}
 p,expected,pub,now=samplePolicy(t)
 p.Grants[0].NotAfter="invalid-time"
 raw,hash=policyWire(t,p)
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err==nil{t.Fatal("unparsable time accepted")}
 p,expected,pub,now=samplePolicy(t)
 other,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 p.Grants=append(p.Grants,SignerGrant{KeyID:KeyID(other),KeyVersion:"alternate-1",Repository:"other/repo",
  Episode:"other-episode",Status:"revoked",NotBefore:"2026-01-01T00:00:00Z",NotAfter:"2027-01-01T00:00:00Z"})
 raw,hash=policyWire(t,p)
 if err:=AuthorizeSigner(raw,hash,pub,expected,now);err!=nil{t.Fatal("a revoked different key must not prevent specific authorized key:",err)}
}
