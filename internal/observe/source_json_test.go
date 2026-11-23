package observe

import (
 "context"
 "errors"
 "fmt"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "testing"
)

func TestGetJSONFailsClosedOnUntrustedSourceBytes(t *testing.T) {
 invalidUTF8 := append([]byte(`{"name":"`), 0xff)
 invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
 cases := map[string][]byte{
  "duplicate-root-key": []byte(`{"status":"success","status":"failure"}`),
  "escaped-duplicate-key": []byte(`{"status":"success","\u0073tatus":"failure"}`),
  "duplicate-inside-nested-array": []byte(`{"data":{"result":[{"metric":{"pod":"a","pod":"b"}}]}}`),
  "invalid-utf8": invalidUTF8,
  "unpaired-high-surrogate": []byte(`{"name":"\ud800"}`),
  "unpaired-low-surrogate": []byte(`{"name":"\udc00"}`),
  "high-then-text": []byte(`{"name":"\ud800A"}`),
  "reversed-pair": []byte(`{"name":"\udc00\ud800"}`),
  "high-then-high": []byte(`{"name":"\ud800\ud801"}`),
  "trailing-document": []byte(`{"ok":true} {"other":false}`),
 }
 for name, payload := range cases {
  t.Run(name, func(t *testing.T) {
   server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    _, _ = w.Write(payload)
   }))
   defer server.Close()
   endpoint, err := url.Parse(server.URL)
   if err != nil { t.Fatal(err) }
   var got map[string]any
   err = getJSON(context.Background(), server.Client(), endpoint, "/api/v1/query", "", &got)
   if !errors.Is(err, ErrUnknown) {
    t.Fatalf("must reject contradictory or malformed native source; got=%v err=%v", got, err)
   }
  })
 }
}

func TestGetJSONKeepsValidUnicodeAndRepeatedKeysInDifferentObjects(t *testing.T) {
 cases := map[string]string{
  "valid-surrogate-pair": `{"name":"\ud83d\ude80"}`,
  "literal-backslash-u": `{"name":"\\ud800"}`,
  "same-key-different-objects": `{"items":[{"name":"a"},{"name":"b"}]}`,
  "escaped-single-key": `{"\u006eame":"example"}`,
 }
 for name, payload := range cases {
  t.Run(name, func(t *testing.T) {
   server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    _, _ = fmt.Fprint(w, payload)
   }))
   defer server.Close()
   endpoint, err := url.Parse(server.URL)
   if err != nil { t.Fatal(err) }
   var got map[string]any
   if err := getJSON(context.Background(), server.Client(), endpoint, "/api/v1/query", "", &got); err != nil {
    t.Fatalf("rejected valid source JSON %q: %v", name, err)
   }
  })
 }
}

func TestCollectRejectsContradictoryDeploymentSourceBeforeOtherReads(t *testing.T) {
 podsRead := false
 promRead := false
 server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  switch {
  case strings.Contains(r.URL.Path, "/deployments/"):
   _, _ = fmt.Fprint(w, `{"metadata":{"uid":"d1","name":"checkout-api","namespace":"golden-demo","resourceVersion":"44","resourceVersion":"45"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"checkout-api"}}}}`)
  case strings.HasSuffix(r.URL.Path, "/pods"):
   podsRead = true
   _, _ = fmt.Fprint(w, `{"metadata":{"resourceVersion":"2"},"items":[]}`)
  case strings.Contains(r.URL.Path, "/query"):
   promRead = true
   _, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":`+validSample+`}}`)
  default:
   w.WriteHeader(http.StatusNotFound)
  }
 }))
 defer server.Close()
 raw, err := Collect(context.Background(), fixture(server.URL))
 if !errors.Is(err, ErrUnknown) || raw != nil {
  t.Fatalf("source contradiction must yield UNKNOWN and no Evidence Bundle: raw=%s err=%v", raw, err)
 }
 if podsRead || promRead { t.Fatal("continued collection after rejected upstream Deployment source") }
}
