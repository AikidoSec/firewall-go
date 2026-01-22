//go:build integration

package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClientInstrumentation(t *testing.T) {
	require.NoError(t, zen.Protect())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	serverHostname := serverURL.Hostname()
	port, err := strconv.ParseUint(serverURL.Port(), 10, 32)
	require.NoError(t, err)
	require.LessOrEqual(t, port, uint64(^uint32(0)))

	t.Run("normal request tracks hostname", func(t *testing.T) {
		agent.State().GetAndClearHostnames()

		resp, err := http.Get(server.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok", string(body))

		hostnames := agent.State().GetAndClearHostnames()
		assert.Equal(t, []aikido_types.Hostname{
			{URL: serverHostname, Port: uint32(port), Hits: 1},
		}, hostnames)
	})

	block := true

	t.Run("blocks request when domain is in block list", func(t *testing.T) {
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Domains: []aikido_types.OutboundDomain{
				{Hostname: serverHostname, Mode: "block"},
			},
			BlockNewOutgoingRequests: false,
			Block:                    &block,
		}
		config.UpdateServiceConfig(cloudConfig, nil)

		client := &http.Client{}
		resp, err := client.Get(server.URL)
		if resp != nil {
			defer resp.Body.Close()
		}

		require.Error(t, err)
		var outboundBlockedErr *zen.OutboundConnectionBlocked
		require.ErrorAs(t, err, &outboundBlockedErr)
		assert.Equal(t, serverHostname, outboundBlockedErr.Hostname)
	})

	t.Run("allows request when domain is in allow list", func(t *testing.T) {
		cloudConfig := &aikido_types.CloudConfigData{
			ConfigUpdatedAt: time.Now().UnixMilli(),
			Domains: []aikido_types.OutboundDomain{
				{Hostname: serverHostname, Mode: "allow"},
			},
			BlockNewOutgoingRequests: true,
			Block:                    &block,
		}
		config.UpdateServiceConfig(cloudConfig, nil)

		client := &http.Client{}
		resp, err := client.Get(server.URL)

		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "ok", string(body))
	})
}
