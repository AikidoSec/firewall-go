//go:build integration

package http_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
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

// Regression test for https://github.com/AikidoSec/firewall-go/issues/400
//
// WrapTransport used to call t.Clone() before injecting the SSRF DialContext.
// Calling Clone() on a transport that has already negotiated h2 shares the
// underlying http2Transport (and its connection pool) between the original and
// the clone. Any subsequent h2 POST to a different authority through that clone
// would fail with EOF.
//
// The fix injects DialContext directly onto the original transport instead.
// Note: this test does not reproduce the EOF locally (httptest loopback doesn't
// trigger it), but documents the scenario and guards against the pattern returning.
func TestHTTPClientInstrumentation_H2ReverseProxy(t *testing.T) {
	require.NoError(t, zen.Protect())
	require.True(t, zen.ShouldProtect(), "protection must be active — test is meaningless without instrumentation wrapping transports")

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only: trusting local httptest cert
	}

	// upstream1 is hit first to prime the wrapped transport's h2 connection
	// pool before the "user" request arrives.
	upstream1 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream1-ok"))
	}))
	upstream1.EnableHTTP2 = true
	upstream1.StartTLS()
	defer upstream1.Close()

	// upstream2 is the target of the user's outbound request.
	var upstream2Proto string
	upstream2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream2Proto = r.Proto
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream2-ok"))
	}))
	upstream2.EnableHTTP2 = true
	upstream2.StartTLS()
	defer upstream2.Close()

	// outboundClient uses a shared transport across both upstreams. The
	// instrumentation will inject SSRF DialContext in-place on first use.
	outboundClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   tlsCfg,
		},
	}

	// Prime the transport with an h2 connection to upstream1 before the user request arrives.
	primeResp, err := outboundClient.Get(upstream1.URL + "/prime")
	require.NoError(t, err, "priming request to upstream1 must succeed")
	primeResp.Body.Close()
	t.Logf("prime request done, upstream1 URL: %s", upstream1.URL)

	// Now simulate the user's reverse-proxy handler making an outbound h2 POST
	// to a different upstream (upstream2) through the same transport.
	var outboundErr string
	inbound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream2.URL+"/v1/chat/completions", strings.NewReader("{}"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := outboundClient.Do(req)
		if err != nil {
			outboundErr = err.Error()
			t.Logf("outbound error: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer inbound.Close()

	resp, err := http.Post(inbound.URL, "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	t.Logf("upstream2 negotiated protocol: %q", upstream2Proto)
	t.Logf("outbound error (empty = none): %q", outboundErr)
	t.Logf("proxy status: %d, body: %q", resp.StatusCode, string(body))

	assert.Equal(t, http.StatusOK, resp.StatusCode, "proxy should not return 502 (EOF from wrapped h2 transport)")
	assert.Equal(t, "upstream2-ok", string(body))
	assert.Equal(t, "HTTP/2.0", upstream2Proto, "outbound request to upstream2 should use HTTP/2")
}
