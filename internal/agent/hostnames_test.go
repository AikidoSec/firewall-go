package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreDomain(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		port           uint32
		expectedCount  uint64
		shouldStore    bool
		setupHostnames map[string]map[uint32]uint64
		calls          int // Number of times to call storeDomain
	}{
		{
			name:          "stores new domain with port",
			domain:        "example.com",
			port:          443,
			expectedCount: 1,
			shouldStore:   true,
			calls:         1,
		},
		{
			name:          "increments count for existing domain and port",
			domain:        "example.com",
			port:          443,
			expectedCount: 4,
			shouldStore:   true,
			setupHostnames: map[string]map[uint32]uint64{
				"example.com": {443: 1},
			},
			calls: 3,
		},
		{
			name:          "creates map for new domain",
			domain:        "newdomain.com",
			port:          8080,
			expectedCount: 1,
			shouldStore:   true,
			setupHostnames: map[string]map[uint32]uint64{
				"example.com": {443: 5},
			},
			calls: 1,
		},
		{
			name:          "handles different ports for same domain",
			domain:        "example.com",
			port:          80,
			expectedCount: 2,
			shouldStore:   true,
			setupHostnames: map[string]map[uint32]uint64{
				"example.com": {443: 10},
			},
			calls: 2,
		},
		{
			name:          "skips storage when port is 0",
			domain:        "example.com",
			port:          0,
			expectedCount: 0,
			shouldStore:   false,
			calls:         1,
		},
		{
			name:          "multiple calls to same domain and port",
			domain:        "example.com",
			port:          443,
			expectedCount: 5,
			shouldStore:   true,
			calls:         5,
		},
		{
			name:          "handles empty domain string",
			domain:        "",
			port:          443,
			expectedCount: 1,
			shouldStore:   true,
			calls:         1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset hostnames before each test
			hostnamesMutex.Lock()
			hostnames = make(map[string]map[uint32]uint64)
			if tt.setupHostnames != nil {
				for domain, ports := range tt.setupHostnames {
					hostnames[domain] = make(map[uint32]uint64)
					for port, count := range ports {
						hostnames[domain][port] = count
					}
				}
			}
			hostnamesMutex.Unlock()

			// Call storeDomain multiple times if specified
			for i := 0; i < tt.calls; i++ {
				storeDomain(tt.domain, tt.port)
			}

			hostnamesMutex.Lock()
			defer hostnamesMutex.Unlock()

			if tt.shouldStore {
				require.Contains(t, hostnames, tt.domain, "domain should be stored")
				assert.Equal(t, tt.expectedCount, hostnames[tt.domain][tt.port], "count should match expected value")
			} else {
				// For port 0, verify it's not stored
				if domainMap, exists := hostnames[tt.domain]; exists {
					_, portExists := domainMap[tt.port]
					assert.False(t, portExists, "port 0 should not be stored")
				} else {
					// Domain might not exist at all if port was 0
					assert.NotContains(t, hostnames, tt.domain, "domain with port 0 should not be stored")
				}
			}
		})
	}
}
