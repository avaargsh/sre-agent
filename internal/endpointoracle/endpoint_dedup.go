package endpointoracle

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

type endpointGroup struct {
	key   string
	ready bool
}

// Track address groups, not Pod identities or transport-port tuples. Exact
// duplicates with matching readiness count once; partial overlap abstains.
func admitEndpointGroup(seen map[string]endpointGroup, family string, addresses []string, ready bool) (bool, error) {
	keys := make([]string, 0, len(addresses))
	local := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		if !validEndpointAddress(family, address) {
			return false, errors.New("invalid EndpointSlice address or address family")
		}
		if family == "FQDN" {
			address = strings.ToLower(strings.TrimSuffix(address, "."))
		} else {
			ip, err := netip.ParseAddr(address)
			if err != nil {
				return false, err
			}
			address = ip.String()
		}
		key := family + ":" + address
		if local[key] {
			return false, errors.New("duplicate address within EndpointSlice endpoint")
		}
		local[key] = true
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return false, errors.New("missing endpoint addresses")
	}
	sort.Strings(keys)
	group := endpointGroup{key: strings.Join(keys, ","), ready: ready}
	duplicate := false
	for _, key := range keys {
		if previous, ok := seen[key]; ok {
			if previous != group {
				return false, errors.New("overlapping EndpointSlice groups or conflicting readiness")
			}
			duplicate = true
		}
	}
	if duplicate {
		return false, nil
	}
	for _, key := range keys {
		seen[key] = group
	}
	return true, nil
}
