package releaseledger

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
)

func privateDir(t *testing.T)string{
 t.Helper()
 root:=t.TempDir()
 if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
 return root
}
func example() Request {
 return Request{
  Tenant:"demo-tenant",Project:"demo-project",ReleaseID:"candidate-001",
  EvidenceSHA256:strings.Repeat("a",64),PolicySHA256:strings.Repeat("b",64),
  Repository:"avaargsh/sre-agent",CommitSHA:strings.Repeat("c",40),
  WorkflowRun:"44999401064",WorkflowAttempt:"1",Episode:"np-calico-egress-001",
  SigningKeyID:strings.Repeat("d",64),SigningKeyVersion:"ci-ephemeral-1",
 }
}
func TestAdmissionReceiptSingleUseAndHashedChain(t *testing.T){
 root:=privateDir(t)
 first,err:=Commit(root,example())
 if err!=nil{t.Fatal(err)}
 if first.SchemaVersion!="sre.lab-release-receipt/v1"||
  first.Status!="LAB_ADMISSION_RECORDED"||first.ProductionReleaseAuthorized||
  first.Sequence!=1||first.PrevHash!=strings.Repeat("0",64)||
  len(first.ReceiptHash)!=64 {t.Fatalf("misleading/incomplete lab-only receipt: %+v",first)}
 records,err:=Read(root);if err!=nil{t.Fatal(err)}
 if len(records)!=1||records[0].ReceiptHash!=first.ReceiptHash{t.Fatalf("journal replay disagrees: %+v",records)}
 if _,err:=Commit(root,example());err==nil{t.Fatal("same release and signature admitted twice")}
 changed:=example();changed.EvidenceSHA256=strings.Repeat("e",64)
 if _,err:=Commit(root,changed);err==nil{t.Fatal("same target accepted different evidence")}
 changed=example();changed.ReleaseID="candidate-002"
 if _,err:=Commit(root,changed);err==nil{t.Fatal("same signature replayed for another release")}
 changed.EvidenceSHA256=strings.Repeat("f",64)
 second,err:=Commit(root,changed);if err!=nil{t.Fatal(err)}
 if second.Sequence!=2||second.PrevHash!=first.ReceiptHash{t.Fatal("receipt chain not linked")}
 records,err=Read(root);if err!=nil||len(records)!=2{t.Fatalf("unable to replay durable ledger: %v %+v",err,records)}
}
func TestConcurrentSameEvidenceOnlyOneWinner(t *testing.T){
 root:=privateDir(t)
 const workers=32
 var wg sync.WaitGroup
 wins:=make(chan Receipt,workers)
 errorsCh:=make(chan error,workers)
 for i:=0;i<workers;i++{
  wg.Add(1)
  go func(){defer wg.Done();r,err:=Commit(root,example());if err==nil{wins<-r}else{errorsCh<-err}}()
 }
 wg.Wait();close(wins);close(errorsCh)
 if len(wins)!=1||len(errorsCh)!=workers-1{
  t.Fatalf("expected exactly one local admission, wins %d, rejected %d",len(wins),len(errorsCh))
 }
 rows,err:=Read(root);if err!=nil||len(rows)!=1{t.Fatalf("local ledger inconsistent: %v %+v",err,rows)}
}
func TestCrashBeforeUnlockFailClosed(t *testing.T){
 root:=privateDir(t)
 if err:=os.Mkdir(filepath.Join(root,".writer"),0700);err!=nil{t.Fatal(err)}
 if _,err:=Commit(root,example());err==nil{t.Fatal("stale crash lock silently stolen")}
 if _,err:=os.Stat(filepath.Join(root,"ledger.jsonl"));!errors.Is(err,os.ErrNotExist){
  t.Fatalf("ledger unexpectedly changed during contested admission: %v",err)
 }
}
func TestTruncatedOrTamperedLedgerFailClosed(t *testing.T){
 for _,attack:=range []string{"remove-newline","change-record","append-malformed","delete-ledger-parent"}{
  t.Run(attack,func(t *testing.T){
   root:=privateDir(t)
   if _,err:=Commit(root,example());err!=nil{t.Fatal(err)}
   filename:=filepath.Join(root,"ledger.jsonl")
   raw,err:=os.ReadFile(filename);if err!=nil{t.Fatal(err)}
   switch attack{
   case "remove-newline":raw=raw[:len(raw)-1]
   case "change-record":raw[0]='X'
   case "append-malformed":raw=append(raw,[]byte(`{"incomplete":true}`)...)
   case "delete-ledger-parent":
    if err:=os.Remove(filename);err!=nil{t.Fatal(err)}
    if err:=os.Mkdir(filename,0700);err!=nil{t.Fatal(err)}
    raw=nil
   }
   if raw!=nil{if err:=os.WriteFile(filename,raw,0600);err!=nil{t.Fatal(err)}}
   if _,err:=Read(root);err==nil{t.Fatal("tampered journal accepted")}
   other:=example();other.ReleaseID="other";other.EvidenceSHA256=strings.Repeat("f",64)
   if _,err:=Commit(root,other);err==nil{t.Fatal("new admission bypassed corrupted journal")}
  })
 }
}
func TestBadRequestAndUntrustedLedgerDirectoryRejected(t *testing.T){
 bads:=[]func(*Request){
  func(r *Request){r.Tenant="../sneaky"},
  func(r *Request){r.Project=""},
  func(r *Request){r.ReleaseID="candidate:1"},
  func(r *Request){r.EvidenceSHA256="short"},
  func(r *Request){r.PolicySHA256="short"},
  func(r *Request){r.WorkflowAttempt="0"},
  func(r *Request){r.CommitSHA="main"},
  func(r *Request){r.SigningKeyID=""},
 }
 for _,bad:=range bads{
  root:=privateDir(t);request:=example();bad(&request)
  if _,err:=Commit(root,request);err==nil{t.Fatalf("invalid request accepted: %+v",request)}
 }
 real:=t.TempDir();link:=filepath.Join(t.TempDir(),"linked")
 if err:=os.Symlink(real,link);err!=nil{t.Fatal(err)}
 if _,err:=Commit(link,example());err==nil{t.Fatal("symlink ledger accepted")}
 permissive:=t.TempDir();if err:=os.Chmod(permissive,0755);err!=nil{t.Fatal(err)}
 if _,err:=Commit(permissive,example());err==nil{t.Fatal("group/world-readable ledger accepted")}
}
func TestReceiptIsCanonicalAndWithoutProductionClaim(t *testing.T){
 root:=privateDir(t);r,err:=Commit(root,example());if err!=nil{t.Fatal(err)}
 b,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(b),`"production_release_authorized":false`)||
  !strings.Contains(string(b),`"status":"LAB_ADMISSION_RECORDED"`){
  t.Fatalf("misleading release receipt %s",b)
 }
}

func TestReadFailsClosedWhileWriterIsUncertain(t *testing.T){
 root:=privateDir(t)
 if err:=os.Mkdir(filepath.Join(root,".writer"),0700);err!=nil{t.Fatal(err)}
 if _,err:=Read(root);err==nil{t.Fatal("read returned successful empty proof despite a writer lock")}
}
func TestTamperedInitializationMarkerFailsClosed(t *testing.T){
 root:=privateDir(t)
 if _,err:=Commit(root,example());err!=nil{t.Fatal(err)}
 marker:=filepath.Join(root,".initialized")
 if err:=os.WriteFile(marker,[]byte("forged reinitialized ledger\n"),0600);err!=nil{t.Fatal(err)}
 if _,err:=Read(root);err==nil{t.Fatal("tampered initialized marker accepted")}
 newEvidence:=example();newEvidence.EvidenceSHA256=strings.Repeat("e",64)
 newEvidence.ReleaseID="candidate-003"
 if _,err:=Commit(root,newEvidence);err==nil{t.Fatal("tampered marker permitted a new admission")}
}


func TestOversizedReceiptDoesNotBrickReadback(t *testing.T) {
 root:=privateDir(t)
 oversized:=example()
 // Valid repository syntax, but an unbounded component would make one
 // persisted JSONL record exceed the reader's 4096-byte record limit.
 oversized.Repository="owner/"+strings.Repeat("r",5000)
 if _,err:=Commit(root,oversized);err==nil{
  t.Fatal("admitted a receipt that the independent reader must reject")
 }
 for _,name:=range []string{".initialized","ledger.jsonl",".writer"}{
  if _,err:=os.Lstat(filepath.Join(root,name));!errors.Is(err,os.ErrNotExist){
   t.Fatalf("failed admission left %s behind: %v",name,err)
  }
 }
 if _,err:=Commit(root,example());err!=nil{
  t.Fatalf("valid admission was poisoned by oversized rejected request: %v",err)
 }
 rows,err:=Read(root)
 if err!=nil||len(rows)!=1{t.Fatalf("valid journal cannot replay: %v %+v",err,rows)}
}
