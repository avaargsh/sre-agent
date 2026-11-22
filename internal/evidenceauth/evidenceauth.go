// Package evidenceauth implements an optional external-trust-key Ed25519
// evidence manifest. A matching signature proves possession of the signing
// key, NOT who authorized the key or that the described cluster was real.
package evidenceauth

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strconv"
 "strings"
)

const (
 DomainSeparator="sre-agent/evidence-manifest/v2\x00"
 maxSources=64
 maxSourceSize=int64(2<<20)
 maxTotalSize=int64(16<<20)
 maxManifestSize=64<<10
 maxEnvelopeSize=128<<10
)
type Expected struct{
 Repository string
 Commit string
 WorkflowRun string
 WorkflowAttempt string
 Episode string
 SigningKeyID string
 SigningKeyVersion string
}
type FileDigest struct{
 Path string `json:"path"`
 SHA256 string `json:"sha256"`
}
type Manifest struct{
 SchemaVersion string `json:"schema_version"`
 Repository string `json:"repository"`
 Commit string `json:"commit_sha"`
 WorkflowRun string `json:"workflow_run_id"`
 WorkflowAttempt string `json:"workflow_run_attempt"`
 Episode string `json:"episode_id"`
 SigningKeyID string `json:"signing_key_id"`
 SigningKeyVersion string `json:"signing_key_version"`
 Files []FileDigest `json:"files"`
}
type Envelope struct{
 SchemaVersion string `json:"schema_version"`
 PayloadBase64 string `json:"payload_base64"`
 SignatureBase64 string `json:"signature_base64"`
}

var repoPattern=regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
var hexPattern=regexp.MustCompile(`^[0-9a-f]{40}// Package evidenceauth implements an optional external-trust-key Ed25519
// evidence manifest. A matching signature proves possession of the signing
// key, NOT who authorized the key or that the described cluster was real.
package evidenceauth

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strconv"
 "strings"
)

const (
 DomainSeparator="sre-agent/evidence-manifest/v2\x00"
 maxSources=64
 maxSourceSize=int64(2<<20)
 maxTotalSize=int64(16<<20)
 maxManifestSize=64<<10
 maxEnvelopeSize=128<<10
)
type Expected struct{
 Repository string
 Commit string
 WorkflowRun string
 WorkflowAttempt string
 Episode string
 SigningKeyID string
 SigningKeyVersion string
}
type FileDigest struct{
 Path string `json:"path"`
 SHA256 string `json:"sha256"`
}
type Manifest struct{
 SchemaVersion string `json:"schema_version"`
 Repository string `json:"repository"`
 Commit string `json:"commit_sha"`
 WorkflowRun string `json:"workflow_run_id"`
 WorkflowAttempt string `json:"workflow_run_attempt"`
 Episode string `json:"episode_id"`
 SigningKeyID string `json:"signing_key_id"`
 SigningKeyVersion string `json:"signing_key_version"`
 Files []FileDigest `json:"files"`
}
type Envelope struct{
 SchemaVersion string `json:"schema_version"`
 PayloadBase64 string `json:"payload_base64"`
 SignatureBase64 string `json:"signature_base64"`
}

var repoPattern=regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
)
var keyIDPattern=regexp.MustCompile(`^[0-9a-f]{64}// Package evidenceauth implements an optional external-trust-key Ed25519
// evidence manifest. A matching signature proves possession of the signing
// key, NOT who authorized the key or that the described cluster was real.
package evidenceauth

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strconv"
 "strings"
)

const (
 DomainSeparator="sre-agent/evidence-manifest/v2\x00"
 maxSources=64
 maxSourceSize=int64(2<<20)
 maxTotalSize=int64(16<<20)
 maxManifestSize=64<<10
 maxEnvelopeSize=128<<10
)
type Expected struct{
 Repository string
 Commit string
 WorkflowRun string
 WorkflowAttempt string
 Episode string
 SigningKeyID string
 SigningKeyVersion string
}
type FileDigest struct{
 Path string `json:"path"`
 SHA256 string `json:"sha256"`
}
type Manifest struct{
 SchemaVersion string `json:"schema_version"`
 Repository string `json:"repository"`
 Commit string `json:"commit_sha"`
 WorkflowRun string `json:"workflow_run_id"`
 WorkflowAttempt string `json:"workflow_run_attempt"`
 Episode string `json:"episode_id"`
 SigningKeyID string `json:"signing_key_id"`
 SigningKeyVersion string `json:"signing_key_version"`
 Files []FileDigest `json:"files"`
}
type Envelope struct{
 SchemaVersion string `json:"schema_version"`
 PayloadBase64 string `json:"payload_base64"`
 SignatureBase64 string `json:"signature_base64"`
}

var repoPattern=regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
)
var keyVersionPattern=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}// Package evidenceauth implements an optional external-trust-key Ed25519
// evidence manifest. A matching signature proves possession of the signing
// key, NOT who authorized the key or that the described cluster was real.
package evidenceauth

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strconv"
 "strings"
)

const (
 DomainSeparator="sre-agent/evidence-manifest/v2\x00"
 maxSources=64
 maxSourceSize=int64(2<<20)
 maxTotalSize=int64(16<<20)
 maxManifestSize=64<<10
 maxEnvelopeSize=128<<10
)
type Expected struct{
 Repository string
 Commit string
 WorkflowRun string
 WorkflowAttempt string
 Episode string
 SigningKeyID string
 SigningKeyVersion string
}
type FileDigest struct{
 Path string `json:"path"`
 SHA256 string `json:"sha256"`
}
type Manifest struct{
 SchemaVersion string `json:"schema_version"`
 Repository string `json:"repository"`
 Commit string `json:"commit_sha"`
 WorkflowRun string `json:"workflow_run_id"`
 WorkflowAttempt string `json:"workflow_run_attempt"`
 Episode string `json:"episode_id"`
 SigningKeyID string `json:"signing_key_id"`
 SigningKeyVersion string `json:"signing_key_version"`
 Files []FileDigest `json:"files"`
}
type Envelope struct{
 SchemaVersion string `json:"schema_version"`
 PayloadBase64 string `json:"payload_base64"`
 SignatureBase64 string `json:"signature_base64"`
}

var repoPattern=regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
)
var episodePattern=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
// KeyID is SHA256 of canonical X.509 SPKI DER, not an arbitrary label.
func KeyID(pub ed25519.PublicKey)string{
 if len(pub)!=ed25519.PublicKeySize{return ""}
 der,err:=x509.MarshalPKIXPublicKey(pub)
 if err!=nil{return ""}
 return digest(der)
}
func validExpected(e Expected)error{
 if !repoPattern.MatchString(e.Repository)||strings.Contains(e.Repository,"..")||
  !hexPattern.MatchString(e.Commit)||!episodePattern.MatchString(e.Episode)||
  !keyIDPattern.MatchString(e.SigningKeyID)||
  !keyVersionPattern.MatchString(e.SigningKeyVersion){
  return errors.New("invalid fixed repository/commit/episode identity")
 }
 n,err:=strconv.ParseUint(e.WorkflowRun,10,64)
 if err!=nil||n==0||strconv.FormatUint(n,10)!=e.WorkflowRun{return errors.New("invalid explicit run ID")}
 a,err:=strconv.ParseUint(e.WorkflowAttempt,10,32)
 if err!=nil||a==0||strconv.FormatUint(a,10)!=e.WorkflowAttempt{return errors.New("invalid explicit run attempt")}
 return nil
}
func isLocal(path string)bool{
 if path==""||!filepath.IsLocal(path)||filepath.Clean(path)!=path||
  strings.Contains(path,"\\")||strings.HasPrefix(path,".")||
  strings.Contains(path,"//")||strings.Contains(path,"\x00")||
  filepath.ToSlash(path)!=path{return false}
 return true
}
// readSource refuses symlink traversal in every existing directory component.
// It verifies a bounded regular file; TOCTOU-free adversarial filesystem
// snapshots must be handled by an external immutable artifact store.
func readSource(root,path string)([]byte,error){
 if !isLocal(path){return nil,fmt.Errorf("nonlocal source path: %q",path)}
 rootInfo,err:=os.Lstat(root)
 if err!=nil||!rootInfo.IsDir()||rootInfo.Mode()&os.ModeSymlink!=0{
  return nil,errors.New("source root must be an existing real directory")
 }
 current:=root
 parts:=strings.Split(path,"/")
 for i,part:=range parts{
  if part==""||part=="."||part==".."{return nil,errors.New("invalid path segment")}
  current=filepath.Join(current,part)
  info,err:=os.Lstat(current)
  if err!=nil{return nil,fmt.Errorf("source path missing: %w",err)}
  if info.Mode()&os.ModeSymlink!=0{return nil,errors.New("symlink source path forbidden")}
  if i<len(parts)-1{
   if !info.IsDir(){return nil,errors.New("source parent is not a directory")}
  }else if !info.Mode().IsRegular()||info.Size()<=0||info.Size()>maxSourceSize{
   return nil,errors.New("source is not a bounded regular nonempty file")
  }
 }
 data,err:=os.ReadFile(current)
 if err!=nil{return nil,err}
 if len(data)==0||int64(len(data))>maxSourceSize{return nil,errors.New("source size changed or is too large")}
 return data,nil
}
func digest(data []byte)string{
 h:=sha256.Sum256(data)
 return hex.EncodeToString(h[:])
}
// Walk JSON token-by-token to reject duplicate object keys at ANY nesting
// depth, before Go's permissive duplicate-key unmarshal. Limit nesting so
// crafted signed inputs cannot exhaust the stack.
func strictJSON(raw []byte,out any)error{
 if len(raw)==0||len(raw)>maxEnvelopeSize{return errors.New("JSON document outside size budget")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 var walk func(int)error
 walk=func(depth int)error{
  if depth>32{return errors.New("JSON exceeds depth budget")}
  t,err:=dec.Token();if err!=nil{return err}
  d,ok:=t.(json.Delim);if !ok{return nil}
  switch d{
  case '{':
   keys:=map[string]bool{}
   for dec.More(){
    k,err:=dec.Token();if err!=nil{return err}
    key,ok:=k.(string)
    if !ok||keys[key]{return errors.New("duplicate/invalid JSON key")}
    keys[key]=true
    if err:=walk(depth+1);err!=nil{return err}
   }
   end,err:=dec.Token()
   if err!=nil||end!=json.Delim('}'){return errors.New("unterminated JSON object")}
  case '[':
   for dec.More(){if err:=walk(depth+1);err!=nil{return err}}
   end,err:=dec.Token()
   if err!=nil||end!=json.Delim(']'){return errors.New("unterminated JSON array")}
  default: return errors.New("invalid JSON delimiter")
  }
  return nil
 }
 if err:=walk(0);err!=nil{return err}
 if _,err:=dec.Token();!errors.Is(err,io.EOF){return errors.New("trailing JSON data")}
 final:=json.NewDecoder(bytes.NewReader(raw))
 final.DisallowUnknownFields()
 if err:=final.Decode(out);err!=nil{return err}
 return nil
}
func checkManifest(m Manifest)error{
 if m.SchemaVersion!="sre.evidence-manifest/v2"{return errors.New("unexpected manifest schema")}
 if err:=validExpected(Expected{Repository:m.Repository,Commit:m.Commit,WorkflowRun:m.WorkflowRun,
  WorkflowAttempt:m.WorkflowAttempt,Episode:m.Episode,SigningKeyID:m.SigningKeyID,
  SigningKeyVersion:m.SigningKeyVersion});err!=nil{return err}
 if len(m.Files)==0||len(m.Files)>maxSources{return errors.New("manifest source count outside budget")}
 previous:=""
 for _,f:=range m.Files{
  if !isLocal(f.Path)||f.Path<=previous{return errors.New("manifest paths must be unique, sorted and local")}
  if len(f.SHA256)!=64{return errors.New("source SHA has wrong length")}
  if _,err:=hex.DecodeString(f.SHA256);err!=nil||strings.ToLower(f.SHA256)!=f.SHA256{
   return errors.New("source SHA must be lowercase hex")
  }
  previous=f.Path
 }
 return nil
}
// Build hashes only explicitly enumerated files, rather than silently
// enumerating a directory and potentially disclosing sensitive secrets.
func Build(root string,paths []string,expected Expected)([]byte,error){
 if err:=validExpected(expected);err!=nil{return nil,err}
 if len(paths)==0||len(paths)>maxSources{return nil,errors.New("bad number of paths")}
 sorted:=append([]string(nil),paths...)
 sort.Strings(sorted)
 manifest:=Manifest{SchemaVersion:"sre.evidence-manifest/v2",Repository:expected.Repository,
  Commit:expected.Commit,WorkflowRun:expected.WorkflowRun,WorkflowAttempt:expected.WorkflowAttempt,
  Episode:expected.Episode,SigningKeyID:expected.SigningKeyID,SigningKeyVersion:expected.SigningKeyVersion,
  Files:make([]FileDigest,0,len(sorted))}
 total:=int64(0)
 previous:=""
 for _,path:=range sorted{
  if path==previous{return nil,errors.New("duplicated input path")}
  source,err:=readSource(root,path);if err!=nil{return nil,err}
  total+=int64(len(source))
  if total>maxTotalSize{return nil,errors.New("total source size budget exceeded")}
  manifest.Files=append(manifest.Files,FileDigest{Path:path,SHA256:digest(source)})
  previous=path
 }
 if err:=checkManifest(manifest);err!=nil{return nil,err}
 raw,err:=json.Marshal(manifest)
 if err!=nil||len(raw)>maxManifestSize{return nil,errors.New("manifest too large")}
 return raw,nil
}
func parseManifest(payload []byte)(Manifest,error){
 var m Manifest
 if len(payload)>maxManifestSize{return m,errors.New("oversized signed manifest")}
 if err:=strictJSON(payload,&m);err!=nil{return m,err}
 if err:=checkManifest(m);err!=nil{return m,err}
 canonical,err:=json.Marshal(m)
 if err!=nil||!bytes.Equal(canonical,payload){return m,errors.New("manifest is not canonical JSON")}
 return m,nil
}
func message(payload []byte)[]byte{
 signed:=make([]byte,0,len(DomainSeparator)+len(payload))
 signed=append(signed,DomainSeparator...)
 return append(signed,payload...)
}
// Sign never generates a key or assigns trust to a key. The caller must
// obtain an authorized private key outside the repository and CI artifacts.
func Sign(manifest []byte,privateKey ed25519.PrivateKey)([]byte,error){
 if len(privateKey)!=ed25519.PrivateKeySize{return nil,errors.New("missing real Ed25519 private key")}
 m,err:=parseManifest(manifest)
 if err!=nil{return nil,err}
 public,ok:=privateKey.Public().(ed25519.PublicKey)
 if !ok||KeyID(public)!=m.SigningKeyID{return nil,errors.New("signing key does not match signed manifest key fingerprint")}
 envelope:=Envelope{SchemaVersion:"sre.evidence-attestation/v2",
  PayloadBase64:base64.StdEncoding.EncodeToString(manifest),
  SignatureBase64:base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey,message(manifest)))}
 return json.Marshal(envelope)
}
// Verify requires external key + repo + exact HEAD + run ID + episode. These
// are NEVER inferred from the untrusted envelope, public key or artifact.
func Verify(root string,envelope []byte,trustedKey ed25519.PublicKey,expected Expected)(Manifest,error){
 var m Manifest
 if err:=validExpected(expected);err!=nil{return m,err}
 if len(trustedKey)!=ed25519.PublicKeySize{return m,errors.New("trusted Ed25519 key must be externally supplied")}
 if KeyID(trustedKey)!=expected.SigningKeyID{return m,errors.New("trusted public key fingerprint disagrees with independently expected key identity")}
 var attestation Envelope
 if err:=strictJSON(envelope,&attestation);err!=nil{return m,err}
 if attestation.SchemaVersion!="sre.evidence-attestation/v2"{return m,errors.New("invalid envelope schema")}
 payload,err:=base64.StdEncoding.Strict().DecodeString(attestation.PayloadBase64)
 if err!=nil{return m,err}
 sig,err:=base64.StdEncoding.Strict().DecodeString(attestation.SignatureBase64)
 if err!=nil||len(sig)!=ed25519.SignatureSize{return m,errors.New("invalid Ed25519 signature encoding")}
 if !ed25519.Verify(trustedKey,message(payload),sig){return m,errors.New("signature not verified against independently trusted key")}
 m,err=parseManifest(payload)
 if err!=nil{return m,err}
 if m.Repository!=expected.Repository||m.Commit!=expected.Commit||
  m.WorkflowRun!=expected.WorkflowRun||m.WorkflowAttempt!=expected.WorkflowAttempt||
  m.Episode!=expected.Episode||m.SigningKeyID!=expected.SigningKeyID||
  m.SigningKeyVersion!=expected.SigningKeyVersion{
  return m,errors.New("signed identity does not match independent expectations")
 }
 total:=int64(0)
 for _,item:=range m.Files{
  data,err:=readSource(root,item.Path);if err!=nil{return m,err}
  total+=int64(len(data))
  if total>maxTotalSize{return m,errors.New("source total exceeds budget")}
  if digest(data)!=item.SHA256{return m,fmt.Errorf("source bytes changed: %s",item.Path)}
 }
 return m,nil
}
