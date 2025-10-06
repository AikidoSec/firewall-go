package api_discovery

import (
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
)

// Merge two APIAuthType slices into one without duplicates.
// It can return nil if both parameters are not slices.
func MergeApiAuthTypes(existing, newAuth []*protos.APIAuthType) []*protos.APIAuthType {
	if len(newAuth) == 0 {
		return existing
	}

	if len(existing) == 0 {
		return newAuth
	}

	result := make([]*protos.APIAuthType, len(existing))
	copy(result, existing)

	for _, auth := range newAuth {
		if !containsAPIAuthType(result, auth) {
			result = append(result, auth)
		}
	}

	return result
}

// Compare two APIAuthType objects for equality.
func isEqualAPIAuthType(a, b *protos.APIAuthType) bool {
	return a.Type == b.Type && a.In == b.In && a.Name == b.Name && a.Scheme == b.Scheme
}

// Check if the slice contains an APIAuthType
func containsAPIAuthType(slice []*protos.APIAuthType, auth *protos.APIAuthType) bool {
	for _, a := range slice {
		if isEqualAPIAuthType(a, auth) {
			return true
		}
	}
	return false
}
