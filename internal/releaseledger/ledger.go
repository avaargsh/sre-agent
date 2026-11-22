// Package releaseledger provides a strictly LOCAL, single-writer lab-only
// admission receipt log. It never deploys or promotes anything and does not
// provide production or distributed exactly-once delivery.
package releaseledger

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
)

const (
 journalName="ledger.jsonl"
 markerName=".initialized"
 lockName=".writer"
 maxJournalBytes=16<<20
 maxRecords=4096
 maxRecordBytes=4096
 domain="sre-agent/lab-release-ledger/v1\x00"
)
var atom=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var keyVersion=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var sha40=regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha64=regexp.MustCompile(`^[0-9a-f]{64}$`)
var episode=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var repository=regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)

type Request struct{
 Tenant string `json:"tenant"`
 Project string `json:"project"`
 ReleaseID string `json:"release_id"`
 EvidenceSHA256 string `json:"attestation_sha256"`
 PolicySHA256 string `json:"policy_sha256"`
 Repository string `json:"repository"`
 CommitSHA string `json:"commit_sha"`
 WorkflowRun string `json:"workflow_run_id"`
 WorkflowAttempt string `json:"workflow_run_attempt"`
 Episode string `json:"episode_id"`
 SigningKeyID string `json:"signing_key_id"`
 SigningKeyVersion string `json:"signing_key_version"`
}
type Receipt struct{
 SchemaVersion string `json:"schema_version"`
 Status string `json:"status"`
 ProductionReleaseAuthorized bool `json:"production_release_authorized"`
 Sequence uint64 `json:"sequence"`
 PrevHash string `json:"previous_receipt_hash"`
 ReceiptHash string `json:"receipt_hash"`
 Request
}
func validDecimal(s string,bits int)bool{
 n,err:=strconv.ParseUint(s,10,bits)
 return err==nil&&n>0&&strconv.FormatUint(n,10)==s
}
func validate(r Request)error{
 if !atom.MatchString(r.Tenant)||!atom.MatchString(r.Project)||!atom.MatchString(r.ReleaseID)||
  !sha64.MatchString(r.EvidenceSHA256)||!sha64.MatchString(r.PolicySHA256)||
  !sha40.MatchString(r.CommitSHA)||!sha64.MatchString(r.SigningKeyID)||
  !keyVersion.MatchString(r.SigningKeyVersion)||!episode.MatchString(r.Episode)||
  !repository.MatchString(r.Repository)||strings.Contains(r.Repository,"..")||
  !validDecimal(r.WorkflowRun,64)||!validDecimal(r.WorkflowAttempt,32){
  return errors.New("incomplete or invalid lab admission identity")
 }
 return nil
}
func hash(r Receipt)string{
 r.ReceiptHash=""
 b,_:=json.Marshal(r)
 h:=sha256.Sum256(append([]byte(domain),b...))
 return hex.EncodeToString(h[:])
}
func labReceipt(req Request,seq uint64,previous string)Receipt{
 r:=Receipt{SchemaVersion:"sre.lab-release-receipt/v1",
  Status:"LAB_ADMISSION_RECORDED",ProductionReleaseAuthorized:false,
  Sequence:seq,PrevHash:previous,Request:req}
 r.ReceiptHash=hash(r)
 return r
}
func ensureDir(root string)error{
 info,err:=os.Lstat(root)
 if err!=nil{return fmt.Errorf("ledger directory missing: %w",err)}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0077!=0{
  return errors.New("ledger must be a real, private 0700 directory")
 }
 return nil
}
func fileState(path string)(bool,error){
 i,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return false,nil}
 if err!=nil{return false,err}
 if !i.Mode().IsRegular()||i.Mode().Perm()&0077!=0{return false,errors.New("ledger file is not a private regular file")}
 return true,nil
}
func syncDir(root string)error{
 f,err:=os.Open(root)
 if err!=nil{return err}
 defer f.Close()
 return f.Sync()
}
func readJournal(root string)([]Receipt,error){
 if err:=ensureDir(root);err!=nil{return nil,err}
 exists,err:=fileState(filepath.Join(root,journalName))
 if err!=nil{return nil,err}
 marker,err:=fileState(filepath.Join(root,markerName))
 if err!=nil{return nil,err}
 if exists!=marker{return nil,errors.New("missing marker or journal after interrupted/tampered commit")}
 if !exists{return []Receipt{},nil}
 markerBytes,err:=os.ReadFile(filepath.Join(root,markerName))
 if err!=nil||string(markerBytes)!="sre-agent/lab-release-ledger/v1\n"{
  return nil,errors.New("initialization marker corrupted (no automatic recovery)")
 }
 st,err:=os.Stat(filepath.Join(root,journalName))
 if err!=nil||st.Size()<=0||st.Size()>maxJournalBytes{return nil,errors.New("journal empty or outside read budget")}
 raw,err:=os.ReadFile(filepath.Join(root,journalName))
 if err!=nil{return nil,err}
 if len(raw)==0||len(raw)>maxJournalBytes||raw[len(raw)-1]!='\n'{
  return nil,errors.New("incomplete journal tail (UNKNOWN, no automatic repair)")
 }
 lines:=bytes.Split(raw[:len(raw)-1],[]byte("\n"))
 if len(lines)==0||len(lines)>maxRecords{return nil,errors.New("journal exceeds record budget")}
 out:=make([]Receipt,0,len(lines))
 seenSlots:=map[string]bool{}
 seenEvidence:=map[string]bool{}
 prev:=strings.Repeat("0",64)
 for i,line:=range lines{
  var r Receipt
  if len(line)==0||len(line)>maxRecordBytes{return nil,errors.New("empty/oversized receipt record")}
  if err:=json.Unmarshal(line,&r);err!=nil{return nil,fmt.Errorf("receipt decode: %w",err)}
  canonical,err:=json.Marshal(r)
  if err!=nil||!bytes.Equal(canonical,line){return nil,errors.New("noncanonical, unknown or duplicate receipt JSON")}
  if err:=validate(r.Request);err!=nil{return nil,err}
  if r.SchemaVersion!="sre.lab-release-receipt/v1"||
   r.Status!="LAB_ADMISSION_RECORDED"||r.ProductionReleaseAuthorized||
   r.Sequence!=uint64(i+1)||r.PrevHash!=prev||r.ReceiptHash!=hash(r){
   return nil,errors.New("tampered/missing/altered receipt chain")
  }
  slot:=r.Tenant+"/"+r.Project+"/"+r.ReleaseID
  if seenSlots[slot]||seenEvidence[r.EvidenceSHA256]{
   return nil,errors.New("duplicate release slot or attestation in existing journal")
  }
  seenSlots[slot]=true
  seenEvidence[r.EvidenceSHA256]=true
  prev=r.ReceiptHash
  out=append(out,r)
 }
 return out,nil
}
// Read independently replays all receipts, requiring canonical entries and
// hash-chain continuity. Hash chains detect accidental mutation; WITHOUT
// an external immutable head they are NOT authenticated against malicious
// complete-log rollback or replacement.
func Read(root string)([]Receipt,error){
 if err:=ensureDir(root);err!=nil{return nil,err}
 if _,err:=os.Lstat(filepath.Join(root,lockName));err==nil{
  return nil,errors.New("uncertain or active ledger writer; readback cannot claim a stable snapshot")
 }else if !errors.Is(err,os.ErrNotExist){return nil,err}
 return readJournal(root)
}

// Commit records a single, LAB ONLY admission on a trusted local POSIX
// filesystem. The caller must independently verify the source signature,
// signer policy and expected CI identity BEFORE calling. No external side
// effects are executed. .writer is an exclusive same-host gate, not a
// distributed lock. SIGKILL may leave .writer in place => fail closed;
// manual reconciliation is required, never automatic lock stealing.
func Commit(root string,req Request)(Receipt,error){
 var zero Receipt
 if err:=validate(req);err!=nil{return zero,err}
 if err:=ensureDir(root);err!=nil{return zero,err}
 lock:=filepath.Join(root,lockName)
 if err:=os.Mkdir(lock,0700);err!=nil{
  return zero,fmt.Errorf("ledger locked/uncertain; no automatic recovery: %w",err)
 }
 uncertain:=false
 completed:=false
 defer func(){
  // Once an IO operation could have changed the durable state, preserve
  // the lock on any error. Operators must reconcile, not blindly retry.
  if !uncertain||completed{
   _=os.Remove(lock)
   _=syncDir(root)
  }
 }()
 if err:=syncDir(root);err!=nil{return zero,err}
 rows,err:=readJournal(root)
 if err!=nil{return zero,err}
 for _,r:=range rows{
  if r.EvidenceSHA256==req.EvidenceSHA256{
   return zero,errors.New("attestation already used by an earlier admission (replay)")
  }
  if r.Tenant==req.Tenant&&r.Project==req.Project&&r.ReleaseID==req.ReleaseID{
   return zero,errors.New("release slot already admitted even with different evidence")
  }
 }
 if len(rows)>=maxRecords{return zero,errors.New("ledger is full; external durable ledger required")}
 prev:=strings.Repeat("0",64)
 if len(rows)>0{prev=rows[len(rows)-1].ReceiptHash}
 receipt:=labReceipt(req,uint64(len(rows)+1),prev)
 line,err:=json.Marshal(receipt)
 if err!=nil{return zero,err}
 // The replay reader rejects individual lines over maxRecordBytes and any
 // journal over maxJournalBytes. Enforce both limits BEFORE creating the
 // initialization marker or opening an append handle: a successful write
 // must remain independently readable.
 if len(line)>maxRecordBytes{
  return zero,errors.New("receipt exceeds journal record budget")
 }
 path:=filepath.Join(root,journalName)
 var currentSize int64
 if len(rows)>0{
  st,err:=os.Stat(path)
  if err!=nil{return zero,err}
  currentSize=st.Size()
 }
 if currentSize+int64(len(line))+1>maxJournalBytes{
  return zero,errors.New("journal capacity exceeded before append")
 }
 if len(rows)==0{
  uncertain=true
  f,err:=os.OpenFile(filepath.Join(root,markerName),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
  if err!=nil{return zero,err}
  if _,err=f.Write([]byte("sre-agent/lab-release-ledger/v1\n"));err!=nil{f.Close();return zero,err}
  if err=f.Sync();err!=nil{f.Close();return zero,err}
  if err=f.Close();err!=nil{return zero,err}
  if err=syncDir(root);err!=nil{return zero,err}
 }
 flags:=os.O_WRONLY|os.O_APPEND
 if len(rows)==0{flags|=os.O_CREATE|os.O_EXCL}
 uncertain=true
 f,err:=os.OpenFile(path,flags,0600)
 if err!=nil{return zero,err}
 if _,err=f.Write(append(line,'\n'));err!=nil{f.Close();return zero,err}
 if err=f.Sync();err!=nil{f.Close();return zero,err}
 if err=f.Close();err!=nil{return zero,err}
 if err=syncDir(root);err!=nil{return zero,err}
 completed=true
 return receipt,nil
}
