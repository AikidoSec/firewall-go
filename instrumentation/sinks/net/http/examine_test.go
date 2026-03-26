//go:build !integration

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
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

func TestExamine_ReturnsEarlyWhenShouldNotProtect(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())
	zen.SetDisabled(true)
	require.False(t, zen.ShouldProtect())

	req, _ := http.NewRequest("GET", "http://example.com/api", http.NoBody)
	err := Examine(req)
	require.NoError(t, err)
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

func TestExamine_BypassedIPSkipsOutboundBlocking(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	originalClient := agent.GetCloudClient()
	defer func() {
		zen.SetDisabled(originalDisabled)
		agent.SetCloudClient(originalClient)
	}()

	require.NoError(t, zen.Protect())
	agent.SetCloudClient(testutil.NewMockCloudClient())

	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		ConfigUpdatedAt: time.Now().UnixMilli(),
		BypassedIPs:     []string{"10.10.10.10"},
		Block:           &block,
		Domains: []aikido_types.OutboundDomain{
			{Hostname: "malicious.com", Mode: "block"},
		},
	}, nil)

	incomingReq := httptest.NewRequest("GET", "/api/fetch?url=http://malicious.com", nil)
	ip := "10.10.10.10"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		RemoteAddress: &ip,
	})
	require.True(t, request.IsBypassed(ctx), "context should be marked as bypassed")

	agent.State().GetAndClearHostnames()
	agent.Stats().GetAndClear()

	outboundReq, _ := http.NewRequestWithContext(ctx, "GET", "http://malicious.com", http.NoBody)
	err := Examine(outboundReq)

	assert.NoError(t, err, "bypassed IP should not trigger outbound blocking")

	stats := agent.Stats().GetAndClear()
	require.Contains(t, stats.Operations, "net/http.Client.Do", "should still track operation stats for bypassed IPs")

	hostnames := agent.State().GetAndClearHostnames()
	require.Len(t, hostnames, 1, "should still report hostname for bypassed IPs")
	assert.Equal(t, "malicious.com", hostnames[0].URL)
}
