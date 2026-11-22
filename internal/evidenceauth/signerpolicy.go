// Signer authorization is a separate, externally digest-pinned policy,
// not a self-asserted field of an evidence manifest or signing envelope.
package evidenceauth

import (
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "strings"
 "time"
)

const maxSignerPolicyBytes=64<<10

// SignerPolicy is a deterministic snapshot supplied from OUTSIDE the signed
// evidence root. The caller must know its SHA256 from an independent trust
// channel; calculating the hash from the same untrusted file is not authority.
type SignerPolicy struct{
 SchemaVersion string `json:"schema_version"`
 Revision string `json:"revision"`
 Grants []SignerGrant `json:"grants"`
}
type SignerGrant struct{
 KeyID string `json:"key_id"`
 KeyVersion string `json:"key_version"`
 Repository string `json:"repository"`
 Episode string `json:"episode"`
 Status string `json:"status"`
 NotBefore string `json:"not_before"`
 NotAfter string `json:"not_after"`
}

// AuthorizeSigner fails closed unless the externally provided digest exactly
// matches a fully validated, unique, in-force grant for the trusted signer
// public key and signed expected identity. It never supplies the trusted
// digest, public key, or current time to its own caller.
func AuthorizeSigner(raw []byte, trustedPolicySHA256 string, trustedKey ed25519.PublicKey, expected Expected, now time.Time)error{
 if len(raw)==0||len(raw)>maxSignerPolicyBytes{
  return errors.New("signer policy missing or outside bounded size")
 }
 if len(trustedPolicySHA256)!=64||trustedPolicySHA256!=strings.ToLower(trustedPolicySHA256){
  return errors.New("explicit canonical pinned policy SHA256 required")
 }
 if _,err:=hex.DecodeString(trustedPolicySHA256);err!=nil{return errors.New("invalid trusted policy digest")}
 if digest(raw)!=trustedPolicySHA256{
  return errors.New("signer policy source differs from independently pinned digest")
 }
 if err:=validExpected(expected);err!=nil{return err}
 if len(trustedKey)!=ed25519.PublicKeySize||KeyID(trustedKey)!=expected.SigningKeyID{
  return errors.New("trusted signer key does not match externally expected key ID")
 }
 if now.IsZero(){return errors.New("trusted verification clock unavailable")}

 var policy SignerPolicy
 if err:=strictJSON(raw,&policy);err!=nil{return fmt.Errorf("invalid signer policy JSON: %w",err)}
 if policy.SchemaVersion!="sre.signer-policy/v1"||
  !keyVersionPattern.MatchString(policy.Revision)||
  len(policy.Grants)==0||len(policy.Grants)>64{
  return errors.New("unsupported or incomplete signer policy")
 }
 active:=false
 revokeFingerprint:=false
 seen:=map[string]bool{}
 for _,grant:=range policy.Grants{
  if !keyIDPattern.MatchString(grant.KeyID)||
   !keyVersionPattern.MatchString(grant.KeyVersion)||
   !repoPattern.MatchString(grant.Repository)||strings.Contains(grant.Repository,"..")||
   !episodePattern.MatchString(grant.Episode)||
   (grant.Status!="active"&&grant.Status!="revoked"){
   return errors.New("malformed signer grant or unrecognized status")
  }
  key:=grant.KeyID+"|"+grant.KeyVersion
  if seen[key]{return errors.New("duplicate signer key version in policy")}
  seen[key]=true
  beginning,err:=time.Parse(time.RFC3339,grant.NotBefore)
  if err!=nil{return errors.New("invalid signer activation time")}
  ending,err:=time.Parse(time.RFC3339,grant.NotAfter)
  if err!=nil||!beginning.Before(ending){return errors.New("invalid signer expiration time")}
  // Compromise/revocation takes precedence over positive grants for the
  // same fingerprint, even if someone copied it under another version.
  if grant.KeyID==expected.SigningKeyID&&grant.Status=="revoked"{
   revokeFingerprint=true
  }
  if grant.KeyID!=expected.SigningKeyID||grant.KeyVersion!=expected.SigningKeyVersion||
   grant.Repository!=expected.Repository||grant.Episode!=expected.Episode{
   continue
  }
  if grant.Status!="active"{
   return errors.New("signer key revoked for this scope")
  }
  if now.Before(beginning)||!now.Before(ending){
   return errors.New("signer key outside authorized validity window")
  }
  active=true
 }
 if revokeFingerprint{return errors.New("signer fingerprint globally revoked by policy")}
 if !active{return errors.New("no matching authorized signer grant for this evidence")}
 return nil
}
