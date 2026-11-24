package observe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/avaargsh/sre-agent/internal/endpointoracle"
	"github.com/avaargsh/sre-agent/internal/oracle"
)

// ServiceTarget is an independently selected Kubernetes Service identity.
// The UID is required because a Service can be deleted and recreated under
// the same namespace/name.
type ServiceTarget struct {
	Namespace string
	Name      string
	UID       string
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

func validateServiceEndpointsConfig(c ServiceEndpointsConfig) (*url.URL, error) {
	target := c.Target
	if !nameOK(target.Namespace) || !nameOK(target.Name) || !eventSelectorUID.MatchString(target.UID) {
		return nil, unknownf("invalid expected Service namespace/name/UID")
	}
	if c.ExpectedTargetPort < 1 || c.ExpectedTargetPort > 65535 {
		return nil, unknownf("invalid expected Service targetPort")
	}
	if len(c.ExpectedSelector) == 0 || len(c.ExpectedSelector) > 32 {
		return nil, unknownf("missing or oversized expected Service selector")
	}
	for key, value := range c.ExpectedSelector {
		if value == "" || !selectorLabelOK(key, value) {
			return nil, unknownf("invalid expected Service selector")
		}
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
	after, err := serviceIdentity(afterRaw, c.Target, c.ExpectedTargetPort, c.ExpectedSelector)
	if err != nil {
		return ServiceEndpointsObservation{}, err
	}
	if before.ResourceVersion != after.ResourceVersion ||
		!bytes.Equal(beforeRaw, afterRaw) ||
		before.CurrentTargetPort != after.CurrentTargetPort ||
		!reflect.DeepEqual(before.CurrentSelector, after.CurrentSelector) {
		return ServiceEndpointsObservation{}, unknownf("Service changed during EndpointSlice collection")
	}
	prediction, err := endpointoracle.Diagnose(beforeRaw, slicesRaw, c.ExpectedTargetPort, c.ExpectedSelector)
	if err != nil {
		return ServiceEndpointsObservation{}, unknownf("invalid or incomplete EndpointSlice evidence")
	}
	if prediction.Service.ServiceUID != c.Target.UID ||
		prediction.Service.ResourceVersion != before.ResourceVersion ||
		prediction.ExpectedSelector == nil ||
		!reflect.DeepEqual(prediction.ExpectedSelector, c.ExpectedSelector) {
		return ServiceEndpointsObservation{}, unknownf("Service and EndpointSlice evidence do not share the selected identity")
	}
	if bounded.Err() != nil {
		return ServiceEndpointsObservation{}, unknownf("Service endpoint collection canceled or deadline exceeded")
	}

	selector := cloneSelector(c.ExpectedSelector)
	// Stable ordering is not required for JSON maps, but constructing the
	// report from a copied map prevents caller mutation after collection.
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	orderedSelector := make(map[string]string, len(selector))
	for _, key := range keys {
		orderedSelector[key] = selector[key]
	}
	report := ServiceEndpointsReport{
		SchemaVersion: "sre.service-endpoints/v1",
		Target: c.Target,
		ExpectedTargetPort: c.ExpectedTargetPort,
		ExpectedSelector: orderedSelector,
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
