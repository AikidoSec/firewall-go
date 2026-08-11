//go:build integration

package http_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fetchHandler(tr *http.Transport) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{Transport: tr}
		resp, err := client.Get(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}

func newInternalTLSServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	internal := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("internal-https-ok"))
	}))
	internal.StartTLS()
	t.Cleanup(internal.Close)

	pool := x509.NewCertPool()
	pool.AddCert(internal.Certificate())
	return internal, pool
}

func assertSSRFBlocked(t *testing.T, inboundURL, path, targetURL string) {
	t.Helper()
	mockClient := testutil.NewMockCloudClient()
	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)
	agent.SetCloudClient(mockClient)

	resp, err := http.Get(inboundURL + path + "?url=" + url.QueryEscape(targetURL))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "got body %q", body)

	select {
	case <-mockClient.AttackDetectedEventSent:
		assert.Equal(t, "ssrf", mockClient.GetCapturedAttack().Kind)
	case <-time.After(2 * time.Second):
		t.Fatal("expected an SSRF attack event")
	}
}

func TestSSRFDialTLSContext(t *testing.T) {
	require.NoError(t, zen.Protect())
	require.True(t, zen.ShouldProtect())
	config.SetBlocking(true)

	internal, pool := newInternalTLSServer(t)
	targetURL := internal.URL + "/"

	trDefault := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	trCustom := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	trCustom.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{RootCAs: pool}}
		return d.DialContext(ctx, network, addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /fetch-tls-custom", fetchHandler(trCustom))
	mux.HandleFunc("GET /fetch-tls-default", fetchHandler(trDefault))

	inbound := httptest.NewServer(mux)
	defer inbound.Close()

	t.Run("default dialer", func(t *testing.T) { assertSSRFBlocked(t, inbound.URL, "/fetch-tls-default", targetURL) })
	t.Run("custom dialer", func(t *testing.T) { assertSSRFBlocked(t, inbound.URL, "/fetch-tls-custom", targetURL) })
}

// DialTLS is deprecated but, like DialTLSContext, bypasses DialContext for non-proxied HTTPS requests.
func TestSSRFDialTLS(t *testing.T) {
	require.NoError(t, zen.Protect())
	require.True(t, zen.ShouldProtect())
	config.SetBlocking(true)

	internal, pool := newInternalTLSServer(t)
	targetURL := internal.URL + "/"

	trCustom := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	trCustom.DialTLS = func(network, addr string) (net.Conn, error) { //nolint:staticcheck // reproducing the deprecated-field bypass
		d := &tls.Dialer{Config: &tls.Config{RootCAs: pool}}
		return d.DialContext(context.Background(), network, addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /fetch-tls-custom", fetchHandler(trCustom))

	inbound := httptest.NewServer(mux)
	defer inbound.Close()

	assertSSRFBlocked(t, inbound.URL, "/fetch-tls-custom", targetURL)
}
