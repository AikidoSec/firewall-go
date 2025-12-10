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
		BlockedIPAddresses: []aikido_types.BlockedIPsData{
			{
				Source:      "test",
				Description: "geo-ip",
				IPs:         []string{"10.0.0.1"},
			},
		},

		BlockedUserAgents: "bot.*",
	})

	t.Run("blocked ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		ip := "10.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx, ip, "/route", "GET")

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is blocked due to geo-ip")
		assert.Contains(t, resp.Message, "10.0.0.1")
	})

	t.Run("blocked user agent", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.Header.Set("User-Agent", "bot-test")
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx, ip, "/route", "GET")

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "identified as a bot")
	})

	t.Run("block route with unapproved ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/admin",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx, ip, "/admin", "GET")

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed")
	})

	t.Run("block route with unapproved ip and nil context", func(t *testing.T) {
		ip := "192.168.1.1"
		resp := OnInitRequest(context.Background(), ip, "/admin", "GET")

		assert.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, resp.Message, "Your IP address is not allowed")
	})

	t.Run("allow route with approved ip", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/admin", nil)
		req.RemoteAddr = "192.168.0.1:4321"
		ip := "192.168.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/admin",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx, ip, "/admin", "GET")

		assert.Nil(t, resp)
	})

	t.Run("nil context", func(t *testing.T) {
		resp := OnInitRequest(context.Background(), "", "", "")

		assert.Nil(t, resp)
	})

	t.Run("allowed request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/route", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		ip := "192.168.1.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		resp := OnInitRequest(ctx, ip, "/route", "GET")

		assert.Nil(t, resp)
	})
}
