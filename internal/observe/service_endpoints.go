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

// ServiceEndpointsReport contains source identity and observation metadata.
// It deliberately makes no source-authentication, root-cause, health or
// recovery claim.
type ServiceEndpointsReport struct {
	SchemaVersion                string            `json:"schema_version"`
	Target                       ServiceTarget     `json:"target"`
	ExpectedTargetPort           int               `json:"expected_target_port"`
	ExpectedSelector             map[string]string `json:"expected_selector"`
	ServiceResourceVersion       string            `json:"service_resource_version"`
	EndpointSliceListResourceVersion string         `json:"endpoint_slice_list_resource_version"`
	ReadyEndpoints               int               `json:"ready_endpoints"`
	Classification               string            `json:"classification"`
	ServiceBeforeSHA256          string            `json:"service_before_sha256"`
	EndpointSlicesSHA256         string            `json:"endpoint_slices_sha256"`
	ServiceAfterSHA256           string            `json:"service_after_sha256"`
	ObservedAt                   string            `json:"observed_at"`
	SourceAuthenticated          bool              `json:"source_authenticated"`
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
	if got.Namespace != target.Namespace || got.Service != target.Name || got.ServiceUID != target.UID || got.ResourceVersion == "" {
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


// CollectServiceEndpoints reads one Service, its label-selected EndpointSlice
// list, and the Service again. A changed UID, resourceVersion or exact source
// bytes invalidates the entire observation. EndpointSlice LIST authorization
// remains namespace-wide in Kubernetes RBAC; labelSelector is not an access
// control boundary. Use only an isolated namespace or a narrower mediator.
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

	beforeRaw, err := getRawJSON(bounded, hc, u, servicePath, c.BearerToken)
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
	slicesPath := "/apis/discovery.k8s.io/v1/namespaces/" + c.Target.Namespace + "/endpointslices?" + query.Encode()
	slicesRaw, err := getRawJSON(bounded, hc, u, slicesPath, c.BearerToken)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}

	afterRaw, err := getRawJSON(bounded, hc, u, servicePath, c.BearerToken)
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
		SchemaVersion: "sre.service-endpoints/v1",
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
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SourceAuthenticated: false,
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}
	return ServiceEndpointsObservation{
		ServiceBeforeRaw: beforeRaw,
		EndpointSlicesRaw: slicesRaw,
		ServiceAfterRaw: afterRaw,
		Report: report,
	}, nil
}
