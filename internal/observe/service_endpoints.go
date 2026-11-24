package observe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/avaargsh/sre-agent/internal/endpointoracle"
	"github.com/avaargsh/sre-agent/internal/oracle"
	"github.com/avaargsh/sre-agent/internal/sourcejson"
)

// ServiceTarget is an independently selected Kubernetes Service identity.
// The UID is required because a Service can be deleted and recreated under
// the same namespace/name.
const maxServiceResourceVersionBytes = 256

type ServiceTarget struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// ServiceEndpointsConfig describes a bounded, read-only Service and
// EndpointSlice observation. Expected configuration must come from an
// operator-controlled baseline, not from the source being inspected.
type ServiceEndpointsConfig struct {
	KubernetesURL       string
	Target              ServiceTarget
	ExpectedTargetPort  int
	ExpectedSelector    map[string]string
	BearerToken         string
	Client              *http.Client
}

// ServiceEndpointsRead records one bounded Kubernetes API read and its exact response binding.
type ServiceEndpointsRead struct {
	Name                         string `json:"name"`
	StartedAt                    string `json:"started_at"`
	CompletedAt                  string `json:"completed_at"`
	RequestResourceVersion       string `json:"request_resource_version,omitempty"`
	RequestResourceVersionMatch  string `json:"request_resource_version_match,omitempty"`
	RequestLabelSelector         string `json:"request_label_selector,omitempty"`
	RequestLimit                 int    `json:"request_limit,omitempty"`
	ResponseResourceVersion      string `json:"response_resource_version"`
	ResponseSHA256                string `json:"response_sha256"`
}

// ServiceEndpointsReport contains source identity, read consistency and observation metadata.
// It deliberately makes no source-authentication, root-cause, health or recovery claim.
type ServiceEndpointsReport struct {
	SchemaVersion                    string                  `json:"schema_version"`
	Target                           ServiceTarget           `json:"target"`
	ExpectedTargetPort               int                     `json:"expected_target_port"`
	ExpectedSelector                 map[string]string       `json:"expected_selector"`
	ServiceResourceVersion           string                  `json:"service_resource_version"`
	EndpointSliceListResourceVersion string                  `json:"endpoint_slice_list_resource_version"`
	ReadyEndpoints                   int                     `json:"ready_endpoints"`
	Classification                   string                  `json:"classification"`
	ServiceBeforeSHA256              string                  `json:"service_before_sha256"`
	EndpointSlicesSHA256             string                  `json:"endpoint_slices_sha256"`
	ServiceAfterSHA256               string                  `json:"service_after_sha256"`
	CollectionStartedAt              string                  `json:"collection_started_at"`
	ReadTimeline                     []ServiceEndpointsRead  `json:"read_timeline"`
	ObservedAt                       string                  `json:"observed_at"`
	SourceAuthenticated              bool                    `json:"source_authenticated"`
}

// ServiceEndpointsObservation preserves the exact bytes from all three
// sequential GET/LIST/GET reads. Treat them as sensitive evidence.
type ServiceEndpointsObservation struct {
	ServiceBeforeRaw  []byte
	EndpointSlicesRaw []byte
	ServiceAfterRaw   []byte
	Report            ServiceEndpointsReport
}

func digestSource(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloneSelector(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func validateServiceEndpointsSelection(target ServiceTarget, expectedTargetPort int, expectedSelector map[string]string) error {
	if !nameOK(target.Namespace) || !nameOK(target.Name) || !eventSelectorUID.MatchString(target.UID) {
		return unknownf("invalid expected Service namespace/name/UID")
	}
	if expectedTargetPort < 1 || expectedTargetPort > 65535 {
		return unknownf("invalid expected Service targetPort")
	}
	if len(expectedSelector) == 0 || len(expectedSelector) > 32 {
		return unknownf("missing or oversized expected Service selector")
	}
	for key, value := range expectedSelector {
		if value == "" || !selectorLabelOK(key, value) {
			return unknownf("invalid expected Service selector")
		}
	}
	return nil
}

func validateServiceEndpointsConfig(c ServiceEndpointsConfig) (*url.URL, error) {
	if err := validateServiceEndpointsSelection(c.Target, c.ExpectedTargetPort, c.ExpectedSelector); err != nil {
		return nil, err
	}
	u, err := endpoint(c.KubernetesURL)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func serviceIdentity(raw []byte, target ServiceTarget, expectedPort int, selector map[string]string) (oracle.Prediction, error) {
	got, err := oracle.DiagnoseWithSelector(raw, expectedPort, selector)
	if err != nil {
		return oracle.Prediction{}, unknownf("invalid or incomplete Service response")
	}
	if got.Namespace != target.Namespace || got.Service != target.Name || got.ServiceUID != target.UID || got.ResourceVersion == "" || got.ResourceVersion == "0" || len(got.ResourceVersion) > maxServiceResourceVersionBytes {
		return oracle.Prediction{}, unknownf("Service response does not match independently selected identity")
	}
	return got, nil
}

// ReplayServiceEndpoints validates the exact pre/post Service snapshots and EndpointSlice list, then recomputes the source-only prediction without contacting Kubernetes.
func ReplayServiceEndpoints(target ServiceTarget, expectedTargetPort int, expectedSelector map[string]string, serviceBeforeRaw, endpointSlicesRaw, serviceAfterRaw []byte) (endpointoracle.Prediction, error) {
	if err := validateServiceEndpointsSelection(target, expectedTargetPort, expectedSelector); err != nil {
		return endpointoracle.Prediction{}, err
	}
	for _, raw := range [][]byte{serviceBeforeRaw, endpointSlicesRaw, serviceAfterRaw} {
		if len(raw) == 0 || len(raw) > maxResponseBytes || sourcejson.Validate(raw) != nil {
			return endpointoracle.Prediction{}, unknownf("invalid or oversized native Service/EndpointSlice JSON")
		}
	}
	before, err := serviceIdentity(serviceBeforeRaw, target, expectedTargetPort, expectedSelector)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}
	after, err := serviceIdentity(serviceAfterRaw, target, expectedTargetPort, expectedSelector)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}
	if before.ResourceVersion != after.ResourceVersion ||
		!bytes.Equal(serviceBeforeRaw, serviceAfterRaw) ||
		before.CurrentTargetPort != after.CurrentTargetPort ||
		!reflect.DeepEqual(before.CurrentSelector, after.CurrentSelector) {
		return endpointoracle.Prediction{}, unknownf("Service changed during EndpointSlice collection")
	}
	prediction, err := endpointoracle.Diagnose(serviceBeforeRaw, endpointSlicesRaw, expectedTargetPort, expectedSelector)
	if err != nil {
		return endpointoracle.Prediction{}, unknownf("invalid or incomplete EndpointSlice evidence")
	}
	if prediction.Service.ServiceUID != target.UID ||
		prediction.Service.ResourceVersion != before.ResourceVersion ||
		prediction.ExpectedSelector == nil ||
		!reflect.DeepEqual(prediction.ExpectedSelector, expectedSelector) {
		return endpointoracle.Prediction{}, unknownf("Service and EndpointSlice evidence do not share the selected identity")
	}
	return prediction, nil
}

// parseCaptureTime accepts only canonical UTC RFC3339Nano timestamps emitted by the collector.
func parseCaptureTime(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != raw {
		return time.Time{}, unknownf("invalid or non-canonical capture timestamp")
	}
	return parsed, nil
}

// ReplayServiceEndpointsObservation verifies that the report's read timeline,
// request-version fence, response versions and digests describe the supplied
// exact raw bytes. It does not authenticate the Kubernetes API server or prove
// that the server honored resourceVersionMatch.
func ReplayServiceEndpointsObservation(target ServiceTarget, expectedTargetPort int, expectedSelector map[string]string, observation ServiceEndpointsObservation) (endpointoracle.Prediction, error) {
	report := observation.Report
	if err := validateServiceEndpointsSelection(target, expectedTargetPort, expectedSelector); err != nil {
		return endpointoracle.Prediction{}, err
	}
	if report.SchemaVersion != "sre.service-endpoints/v2" ||
		report.Target != target ||
		report.ExpectedTargetPort != expectedTargetPort ||
		!reflect.DeepEqual(report.ExpectedSelector, expectedSelector) ||
		report.SourceAuthenticated ||
		len(report.ReadTimeline) != 3 {
		return endpointoracle.Prediction{}, unknownf("invalid Service endpoint capture report")
	}

	prediction, err := ReplayServiceEndpoints(
		target, expectedTargetPort, expectedSelector,
		observation.ServiceBeforeRaw, observation.EndpointSlicesRaw, observation.ServiceAfterRaw,
	)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}
	before, err := serviceIdentity(observation.ServiceBeforeRaw, target, expectedTargetPort, expectedSelector)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}
	after, err := serviceIdentity(observation.ServiceAfterRaw, target, expectedTargetPort, expectedSelector)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}

	if report.ServiceResourceVersion != before.ResourceVersion ||
		report.EndpointSliceListResourceVersion != prediction.ListResourceVersion ||
		report.ReadyEndpoints != prediction.ReadyEndpoints ||
		report.Classification != prediction.Classification ||
		report.ServiceBeforeSHA256 != digestSource(observation.ServiceBeforeRaw) ||
		report.EndpointSlicesSHA256 != digestSource(observation.EndpointSlicesRaw) ||
		report.ServiceAfterSHA256 != digestSource(observation.ServiceAfterRaw) {
		return endpointoracle.Prediction{}, unknownf("capture report does not bind exact source bytes and replay result")
	}

	reads := report.ReadTimeline
	wantNames := []string{"service_get_before", "endpoint_slice_list", "service_get_after"}
	wantVersions := []string{before.ResourceVersion, prediction.ListResourceVersion, after.ResourceVersion}
	wantDigests := []string{
		digestSource(observation.ServiceBeforeRaw),
		digestSource(observation.EndpointSlicesRaw),
		digestSource(observation.ServiceAfterRaw),
	}
	for i := range reads {
		if reads[i].Name != wantNames[i] ||
			reads[i].ResponseResourceVersion != wantVersions[i] ||
			reads[i].ResponseSHA256 != wantDigests[i] {
			return endpointoracle.Prediction{}, unknownf("capture read timeline does not match source evidence")
		}
	}
	if reads[0].RequestResourceVersion != "" || reads[0].RequestResourceVersionMatch != "" ||
		reads[0].RequestLabelSelector != "" || reads[0].RequestLimit != 0 ||
		reads[1].RequestResourceVersion != before.ResourceVersion ||
		reads[1].RequestResourceVersionMatch != "NotOlderThan" ||
		reads[1].RequestLabelSelector != "kubernetes.io/service-name="+target.Name ||
		reads[1].RequestLimit != 129 ||
		reads[2].RequestResourceVersion != "" || reads[2].RequestResourceVersionMatch != "" ||
		reads[2].RequestLabelSelector != "" || reads[2].RequestLimit != 0 {
		return endpointoracle.Prediction{}, unknownf("EndpointSlice LIST is not bound to the selected Service resourceVersion")
	}

	collectionStart, err := parseCaptureTime(report.CollectionStartedAt)
	if err != nil {
		return endpointoracle.Prediction{}, err
	}
	collectionEnd, err := parseCaptureTime(report.ObservedAt)
	if err != nil || collectionEnd.Before(collectionStart) ||
		collectionEnd.Sub(collectionStart) > maxCollectionDuration {
		return endpointoracle.Prediction{}, unknownf("invalid or over-budget Service endpoint collection time window")
	}
	previousEnd := collectionStart
	for _, read := range reads {
		started, err := parseCaptureTime(read.StartedAt)
		if err != nil {
			return endpointoracle.Prediction{}, err
		}
		completed, err := parseCaptureTime(read.CompletedAt)
		if err != nil || completed.Before(started) || started.Before(previousEnd) {
			return endpointoracle.Prediction{}, unknownf("invalid or overlapping source read intervals")
		}
		previousEnd = completed
	}
	if collectionEnd.Before(previousEnd) {
		return endpointoracle.Prediction{}, unknownf("collection window ends before final source read")
	}
	return prediction, nil
}

// CollectServiceEndpoints reads one Service, its label-selected EndpointSlice
// list, and the Service again. The list is requested at least as fresh as the
// first Service resourceVersion. A changed Service UID, version or exact bytes
// invalidates the observation. EndpointSlice LIST authorization remains
// namespace-wide in Kubernetes RBAC; labelSelector is not an access control
// boundary. Use only an isolated namespace or a narrower mediator.
func CollectServiceEndpoints(ctx context.Context, c ServiceEndpointsConfig) (ServiceEndpointsObservation, error) {
	u, err := validateServiceEndpointsConfig(c)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, maxCollectionDuration)
	defer cancel()
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}
	hc := client(Config{Client: c.Client})
	servicePath := "/api/v1/namespaces/" + c.Target.Namespace + "/services/" + c.Target.Name
	collectionStarted := time.Now()

	beforeStarted := time.Now()
	beforeRaw, err := getRawJSON(bounded, hc, u, servicePath, c.BearerToken)
	beforeCompleted := time.Now()
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	before, err := serviceIdentity(beforeRaw, c.Target, c.ExpectedTargetPort, c.ExpectedSelector)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}

	query := url.Values{}
	query.Set("labelSelector", "kubernetes.io/service-name="+c.Target.Name)
	query.Set("limit", strconv.Itoa(129)) // 128 accepted plus one to detect overflow.
	// Ask the API server for a collection snapshot no older than the
	// selected Service version. Never retry without this freshness fence.
	query.Set("resourceVersion", before.ResourceVersion)
	query.Set("resourceVersionMatch", "NotOlderThan")
	slicesPath := "/apis/discovery.k8s.io/v1/namespaces/" + c.Target.Namespace + "/endpointslices?" + query.Encode()

	slicesStarted := time.Now()
	slicesRaw, err := getRawJSON(bounded, hc, u, slicesPath, c.BearerToken)
	slicesCompleted := time.Now()
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}

	afterStarted := time.Now()
	afterRaw, err := getRawJSON(bounded, hc, u, servicePath, c.BearerToken)
	afterCompleted := time.Now()
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	collectionCompleted := time.Now()
	after, err := serviceIdentity(afterRaw, c.Target, c.ExpectedTargetPort, c.ExpectedSelector)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	prediction, err := ReplayServiceEndpoints(c.Target, c.ExpectedTargetPort, c.ExpectedSelector, beforeRaw, slicesRaw, afterRaw)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}

	selector := cloneSelector(c.ExpectedSelector)
	report := ServiceEndpointsReport{
		SchemaVersion: "sre.service-endpoints/v2",
		Target: c.Target,
		ExpectedTargetPort: c.ExpectedTargetPort,
		ExpectedSelector: selector,
		ServiceResourceVersion: before.ResourceVersion,
		EndpointSliceListResourceVersion: prediction.ListResourceVersion,
		ReadyEndpoints: prediction.ReadyEndpoints,
		Classification: prediction.Classification,
		ServiceBeforeSHA256: digestSource(beforeRaw),
		EndpointSlicesSHA256: digestSource(slicesRaw),
		ServiceAfterSHA256: digestSource(afterRaw),
		CollectionStartedAt: collectionStarted.UTC().Format(time.RFC3339Nano),
		ReadTimeline: []ServiceEndpointsRead{
			{
				Name: "service_get_before",
				StartedAt: beforeStarted.UTC().Format(time.RFC3339Nano),
				CompletedAt: beforeCompleted.UTC().Format(time.RFC3339Nano),
				ResponseResourceVersion: before.ResourceVersion,
				ResponseSHA256: digestSource(beforeRaw),
			},
			{
				Name: "endpoint_slice_list",
				StartedAt: slicesStarted.UTC().Format(time.RFC3339Nano),
				CompletedAt: slicesCompleted.UTC().Format(time.RFC3339Nano),
				RequestResourceVersion: before.ResourceVersion,
				RequestResourceVersionMatch: "NotOlderThan",
				RequestLabelSelector: "kubernetes.io/service-name="+c.Target.Name,
				RequestLimit: 129,
				ResponseResourceVersion: prediction.ListResourceVersion,
				ResponseSHA256: digestSource(slicesRaw),
			},
			{
				Name: "service_get_after",
				StartedAt: afterStarted.UTC().Format(time.RFC3339Nano),
				CompletedAt: afterCompleted.UTC().Format(time.RFC3339Nano),
				ResponseResourceVersion: after.ResourceVersion,
				ResponseSHA256: digestSource(afterRaw),
			},
		},
		ObservedAt: collectionCompleted.UTC().Format(time.RFC3339Nano),
		SourceAuthenticated: false,
	}
	observation := ServiceEndpointsObservation{
		ServiceBeforeRaw: beforeRaw,
		EndpointSlicesRaw: slicesRaw,
		ServiceAfterRaw: afterRaw,
		Report: report,
	}
	if _, err := ReplayServiceEndpointsObservation(c.Target, c.ExpectedTargetPort, c.ExpectedSelector, observation); err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}
	return observation, nil
}
