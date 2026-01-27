//go:build !integration

package http

import (
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPort(t *testing.T) {
	tests := []struct {
		url      string
		expected uint32
	}{
		{"http://example.com", 80},
		{"https://example.com", 443},
		{"http://example.com:8080", 8080},
		{"https://example.com:9443", 9443},
		{"ftp://example.com", 0},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", tt.url, http.NoBody)
		assert.Equal(t, tt.expected, getPort(req), tt.url)
	}
}

func TestExamine_TracksOperationStats(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	// Clear stats before test
	agent.Stats().GetAndClear()

	// Make multiple HTTP requests
	req1, _ := http.NewRequest("GET", "http://example.com/api", http.NoBody)
	req2, _ := http.NewRequest("POST", "https://api.example.com/data", http.NoBody)
	req3, _ := http.NewRequest("GET", "http://example.com/test", http.NoBody)

	_ = Examine(req1)
	_ = Examine(req2)
	_ = Examine(req3)

	// Get stats and verify operations were tracked
	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "net/http.Client.Do")
	require.Equal(t, 3, stats.Operations["net/http.Client.Do"].Total, "should track 3 HTTP calls")
}
