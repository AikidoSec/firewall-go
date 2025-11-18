package state

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
			c := NewCollector()

			// Call storeDomain multiple times if specified
			for i := 0; i < tt.calls; i++ {
				c.StoreHostname(tt.domain, tt.port)
			}

			result := c.GetAndClearHostnames()

			if tt.shouldStore {
				// Find the hostname in results
				found := false
				for _, h := range result {
					if h.URL == tt.domain && h.Port == tt.port {
						assert.Equal(t, tt.expectedCount, h.Hits, "count should match expected value")
						found = true
						break
					}
				}
				require.True(t, found, "domain %s with port %d should be stored", tt.domain, tt.port)
			} else {
				// Verify this domain/port combo is not in results
				for _, h := range result {
					if h.URL == tt.domain {
						assert.NotEqual(t, uint32(0), h.Port, "port 0 should not be stored for domain %s", tt.domain)
					}
				}
			}
		})
	}
}
