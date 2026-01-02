package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestOnInitRequest(t *testing.T) {
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
		Endpoints: []aikido_types.Endpoint{
			{
				Method:             "GET",
				Route:              "/admin",
				AllowedIPAddresses: []string{"192.168.0.1"},
			},
		},
	}, &aikido_types.ListsConfigData{
		AllowedIPAddresses: []aikido_types.IPList{
			{
				Source:      "test-allowed",
				Description: "Test allowed IPs",
				IPs:         []string{"8.8.8.100", "8.8.8.8", "2001:4860:4860::/48", "2001:db8::/32"},
			},
		},
		BlockedIPAddresses: []aikido_types.IPList{
			{
				Source:      "test",
				Description: "geo-ip",
				IPs:         []string{"10.0.0.1"},
			},
		},
		BlockedUserAgents: "bot.*",
	})

	t.Run("blocked ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", http.NoBody)
		req.RemoteAddr = "10.0.0.1:1234"
		ip := "10.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is blocked due to geo-ip")
		assert.Contains(t, resp.Message, "10.0.0.1")
	})

	t.Run("blocked user agent", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", http.NoBody)
		req.Header.Set("User-Agent", "bot-test")
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "identified as a bot")
	})

	t.Run("block route with unapproved ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", http.NoBody)
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/admin",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed")
	})

	t.Run("allow route with approved ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", http.NoBody)
		req.RemoteAddr = "192.168.0.1:4321"
		ip := "192.168.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/admin",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.Nil(t, resp)
	})

	t.Run("nil context", func(t *testing.T) {
		resp := OnInitRequest(context.Background())

		assert.Nil(t, resp)
	})

	t.Run("allowed request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", http.NoBody)
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.Nil(t, resp)
	})

	t.Run("blocked by global allow list", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "203.0.114.1:1234"
		ip := "203.0.114.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed to access this resource")
		assert.Contains(t, resp.Message, "203.0.114.1")
	})

	t.Run("private IPs always allowed even when allowlist is set", func(t *testing.T) {
		// Private IPs should always be allowed
		for _, testIP := range []string{"127.0.0.1", "192.168.1.1", "172.16.0.1"} {
			req, _ := http.NewRequest("GET", "/route", nil)
			req.RemoteAddr = testIP + ":1234"
			ip := testIP
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/route",
				RemoteAddress: &ip,
			})

			resp := OnInitRequest(ctx)
			// Should not be blocked by allow list (may be blocked by other checks, but not allow list)
			// In this case, should pass since no other blocking is configured
			assert.Nil(t, resp, "Private IP %s should be allowed", testIP)
		}
	})

	t.Run("allowed by global allow list", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "8.8.8.100:1234"
		ip := "8.8.8.100"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		// Should pass allow list check and continue
		// (may still be blocked by other checks, but allow list check passes)
		// In this case, it should pass all checks since no other blocking is configured
		assert.Nil(t, resp)
	})

	t.Run("global allow list checked before block list", func(t *testing.T) {
		// Public IP is in both allow and block lists
		// Allow list is checked first, so if IP is not in allow list, it's blocked before block list check
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "8.8.4.4:1234"
		ip := "8.8.4.4"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		// Should be blocked by allow list first (before block list check)
		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed to access this resource")
	})

	t.Run("public IPv6 address in global allow list", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "[2001:4860:4860::8888]:1234"
		ip := "2001:4860:4860::8888"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		// Should pass allow list check
		assert.Nil(t, resp)
	})

	t.Run("private IPv6 addresses always allowed", func(t *testing.T) {
		// Private IPv6 addresses should always be allowed
		for _, testIP := range []string{"::1", "fc00::1", "fe80::1"} {
			req, _ := http.NewRequest("GET", "/route", nil)
			req.RemoteAddr = "[" + testIP + "]:1234"
			ip := testIP
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/route",
				RemoteAddress: &ip,
			})

			resp := OnInitRequest(ctx)
			// Should not be blocked by allow list
			assert.Nil(t, resp, "Private IPv6 %s should be allowed", testIP)
		}
	})

	t.Run("IPv6 address not in global allow list", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "[2001:db9::1]:1234"
		ip := "2001:db9::1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx)

		// Should be blocked by allow list
		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed to access this resource")
	})
}
