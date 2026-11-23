package observe

import (
 "context"
 "errors"
 "testing"
)

func TestCollectRejectsInvalidInstantVectorLabelsets(t *testing.T) {
 cases:=map[string]string{
  "duplicate-labelsets-different-key-order":`[{"metric":{"namespace":"golden-demo","pod":"checkout-0"},"value":[1795350600,"0.2"]},{"metric":{"pod":"checkout-0","namespace":"golden-demo"},"value":[1795350600,"0.3"]}]`,
  "duplicate-unlabeled-aggregate":`[{"metric":{},"value":[1795350600,"0.2"]},{"metric":{},"value":[1795350600,"0.3"]}]`,
  "missing-metric-object":`[{"value":[1795350600,"0.2"]}]`,
  "empty-metric-label-name":`[{"metric":{"":"bad"},"value":[1795350600,"0.2"]}]`,
 }
 for name,series:=range cases{
  t.Run(name,func(t *testing.T){
   srv,_:=serve(t,series,false)
   raw,err:=Collect(context.Background(),fixture(srv.URL))
   if !errors.Is(err,ErrUnknown)||raw!=nil{
    t.Fatalf("invalid instant vector must not publish evidence: bytes=%q err=%v",raw,err)
   }
  })
 }
}

func TestCollectAcceptsDistinctInstantVectorLabelsets(t *testing.T){
 series:=`[{"metric":{"namespace":"golden-demo","pod":"checkout-0"},"value":[1795350600,"0.2"]},{"metric":{"pod":"checkout-1","namespace":"golden-demo"},"value":[1795350600,"0.3"]}]`
 srv,_:=serve(t,series,false)
 raw,err:=Collect(context.Background(),fixture(srv.URL))
 if err!=nil||len(raw)==0{t.Fatalf("valid unique instant vector rejected: bytes=%d err=%v",len(raw),err)}
}
