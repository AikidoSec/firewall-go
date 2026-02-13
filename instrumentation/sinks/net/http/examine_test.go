//go:build !integration

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
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

func TestExamine_SSRF_BlocksPrivateIPFromUserInput(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	// Set up a request context where query contains the private IP
	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2F10.0.0.1%2Finternal", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Create outgoing request to private IP with the request context
	outgoingReq, _ := http.NewRequest("GET", "http://10.0.0.1/internal", http.NoBody)
	outgoingReq = outgoingReq.WithContext(ctx)

	err := Examine(outgoingReq)
	require.Error(t, err, "should block request to private IP found in user input")
}

func TestExamine_SSRF_AllowsPublicIP(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2F8.8.8.8%2Fdns", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Outgoing request to public IP should not be blocked
	outgoingReq, _ := http.NewRequest("GET", "http://8.8.8.8/dns", http.NoBody)
	outgoingReq = outgoingReq.WithContext(ctx)

	err := Examine(outgoingReq)
	require.NoError(t, err, "should not block request to public IP")
}

func TestExamine_SSRF_AllowsPrivateIPNotInUserInput(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer func() {
		config.SetBlocking(originalBlocking)
		agent.SetCloudClient(originalClient)
	}()

	mockClient := testutil.NewMockCloudClient()
	agent.SetCloudClient(mockClient)

	// User input contains a different hostname, not the private IP
	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2Fexample.com", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Outgoing request to private IP that is NOT in user input should pass
	outgoingReq, _ := http.NewRequest("GET", "http://10.0.0.1/internal", http.NoBody)
	outgoingReq = outgoingReq.WithContext(ctx)

	err := Examine(outgoingReq)
	require.NoError(t, err, "should not block private IP not originating from user input")
}
