package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnInitRequest_IPAllowList_UsesAuthorizationIP tests that IP allow/block
// enforcement uses the authorization IP (socket IP by default) instead of the
// header-derived IP, preventing header spoofing attacks.
func TestOnInitRequest_IPAllowList_UsesAuthorizationIP(t *testing.T) {
	// Setup: Configure an IP allow list that only allows 5.6.7.8
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		ConfigUpdatedAt: time.Now().UnixMilli(),
		Block:           &block,
	}, &aikido_types.ListsConfigData{
		AllowedIPAddresses: []aikido_types.IPList{
			{
				Description: "Test allow list",
				IPs:         []string{"5.6.7.8"},
			},
		},
	})
	defer config.ResetServiceConfig()

	t.Run("blocks request when socket IP is not in allow list, even with spoofed header", func(t *testing.T) {
		// Attacker tries to spoof X-Forwarded-For header with an allowed IP
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234" // Real socket IP (not in allow list)
		req.Header.Set("X-Forwarded-For", "5.6.7.8") // Spoofed header (in allow list)

		socketIP := "1.2.3.4"
		headerIP := "5.6.7.8"

		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:          "test",
			Route:           "/test",
			RemoteAddress:   &headerIP,      // This is what GetClientIP() returns
			AuthorizationIP: &socketIP,      // This is what GetClientIPForAuthorization() returns
		})

		// Should block because the authorization IP (socket IP) is not in the allow list
		response := OnInitRequest(ctx)
		require.NotNil(t, response, "Expected request to be blocked")
		assert.Equal(t, 403, response.StatusCode)
		assert.Contains(t, response.Message, "1.2.3.4", "Error message should show the real IP")
	})

	t.Run("allows request when socket IP is in allow list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234" // Real socket IP (in allow list)
		req.Header.Set("X-Forwarded-For", "1.2.3.4") // Header IP (not in allow list)

		socketIP := "5.6.7.8"
		headerIP := "1.2.3.4"

		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:          "test",
			Route:           "/test",
			RemoteAddress:   &headerIP,
			AuthorizationIP: &socketIP,
		})

		// Should allow because the authorization IP (socket IP) is in the allow list
		response := OnInitRequest(ctx)
		assert.Nil(t, response, "Expected request to be allowed")
	})

	t.Run("allows request when AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is enabled and header IP is in allow list", func(t *testing.T) {
		// This simulates a properly configured reverse proxy setup
		t.Setenv("AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS", "true")

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234" // Socket IP (not in allow list)
		req.Header.Set("X-Forwarded-For", "5.6.7.8") // Header IP (in allow list)

		// When AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS is enabled, both should be the header IP
		headerIP := "5.6.7.8"

		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:          "test",
			Route:           "/test",
			RemoteAddress:   &headerIP,
			AuthorizationIP: &headerIP, // Now trusts the header
		})

		// Should allow because we're explicitly trusting the proxy
		response := OnInitRequest(ctx)
		assert.Nil(t, response, "Expected request to be allowed when proxy is trusted")
	})
}

// TestOnInitRequest_IPBlockList_UsesAuthorizationIP tests that IP block list
// enforcement uses the authorization IP.
func TestOnInitRequest_IPBlockList_UsesAuthorizationIP(t *testing.T) {
	// Setup: Configure an IP block list that blocks 5.6.7.8
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		ConfigUpdatedAt: time.Now().UnixMilli(),
		Block:           &block,
	}, &aikido_types.ListsConfigData{
		BlockedIPAddresses: []aikido_types.IPList{
			{
				Description: "Test block list",
				IPs:         []string{"5.6.7.8"},
			},
		},
	})
	defer config.ResetServiceConfig()

	t.Run("allows request when socket IP is not in block list, even with spoofed header", func(t *testing.T) {
		// Attacker tries to spoof X-Forwarded-For header with a blocked IP
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "1.2.3.4:1234" // Real socket IP (not in block list)
		req.Header.Set("X-Forwarded-For", "5.6.7.8") // Spoofed header (in block list)

		socketIP := "1.2.3.4"
		headerIP := "5.6.7.8"

		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:          "test",
			Route:           "/test",
			RemoteAddress:   &headerIP,
			AuthorizationIP: &socketIP,
		})

		// Should allow because the authorization IP (socket IP) is not in the block list
		response := OnInitRequest(ctx)
		assert.Nil(t, response, "Expected request to be allowed")
	})

	t.Run("blocks request when socket IP is in block list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "5.6.7.8:1234" // Real socket IP (in block list)
		req.Header.Set("X-Forwarded-For", "1.2.3.4") // Header IP (not in block list)

		socketIP := "5.6.7.8"
		headerIP := "1.2.3.4"

		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:          "test",
			Route:           "/test",
			RemoteAddress:   &headerIP,
			AuthorizationIP: &socketIP,
		})

		// Should block because the authorization IP (socket IP) is in the block list
		response := OnInitRequest(ctx)
		require.NotNil(t, response, "Expected request to be blocked")
		assert.Equal(t, 403, response.StatusCode)
		assert.Contains(t, response.Message, "5.6.7.8", "Error message should show the real IP")
	})
}

// TestOnInitRequest_PrivateIPsAlwaysAllowed tests that private IPs are always
// allowed even when an allow list is configured (matching Node.js behavior).
func TestOnInitRequest_PrivateIPsAlwaysAllowed(t *testing.T) {
	// Setup: Configure an IP allow list that only allows 5.6.7.8
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		ConfigUpdatedAt: time.Now().UnixMilli(),
		Block:           &block,
	}, &aikido_types.ListsConfigData{
		AllowedIPAddresses: []aikido_types.IPList{
			{
				Description: "Test allow list",
				IPs:         []string{"5.6.7.8"},
			},
		},
	})
	defer config.ResetServiceConfig()

	privateIPs := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"::1",
		"fc00::1",
	}

	for _, privateIP := range privateIPs {
		t.Run("allows private IP "+privateIP, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = privateIP + ":1234"

			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:          "test",
				Route:           "/test",
				RemoteAddress:   &privateIP,
				AuthorizationIP: &privateIP,
			})

			response := OnInitRequest(ctx)
			assert.Nil(t, response, "Expected private IP to be allowed")
		})
	}
}
