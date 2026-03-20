//go:build !integration

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRoundTripper struct{}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

func TestWrapTransport_NonHTTPTransport_ReturnsSameInstance(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)
	agent.SetCloudClient(testutil.NewMockCloudClient())

	rt := &mockRoundTripper{}
	result := WrapTransport(rt)
	assert.Same(t, rt, result, "should return same instance for non-*http.Transport")
}

func TestWrapTransport_CachesWrappedTransport(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)
	agent.SetCloudClient(testutil.NewMockCloudClient())

	// Clear cache from previous tests
	wrappedTransports.Range(func(key, value any) bool {
		wrappedTransports.Delete(key)
		return true
	})

	tr := &http.Transport{}
	result1 := WrapTransport(tr)
	result2 := WrapTransport(tr)

	assert.Same(t, result1, result2, "should return cached wrapper for repeated calls")
	assert.NotSame(t, tr, result1, "should return a different instance than original")

	wrapped, ok := result1.(*ssrfTransport)
	assert.True(t, ok, "should return an *ssrfTransport")
	assert.NotSame(t, tr, wrapped.inner, "inner transport should be a clone, not the original")
}

func TestWrapTransport_DoesNotDoubleWrap(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	defer agent.SetCloudClient(originalClient)
	agent.SetCloudClient(testutil.NewMockCloudClient())

	wrapped := &ssrfTransport{inner: &http.Transport{}}
	result := WrapTransport(wrapped)
	assert.Same(t, wrapped, result, "should not double-wrap an ssrfTransport")
}

func TestWrapTransport_ReturnsUnwrappedWhenProtectionDisabled(t *testing.T) {
	originalDisabled := zen.IsDisabled()
	defer zen.SetDisabled(originalDisabled)

	zen.SetDisabled(true)

	tr := &http.Transport{}
	result := WrapTransport(tr)
	assert.Same(t, tr, result, "should return original transport when protection is disabled")
}

func TestPortFromURL(t *testing.T) {
	t.Run("returns explicit port", func(t *testing.T) {
		u, _ := url.Parse("http://example.com:8080/path")
		assert.Equal(t, uint32(8080), portFromURL(u))
	})

	t.Run("returns 443 for https", func(t *testing.T) {
		u, _ := url.Parse("https://example.com/path")
		assert.Equal(t, uint32(443), portFromURL(u))
	})

	t.Run("returns 80 for http", func(t *testing.T) {
		u, _ := url.Parse("http://example.com/path")
		assert.Equal(t, uint32(80), portFromURL(u))
	})
}

func TestRecordRedirect(t *testing.T) {
	t.Run("nil reqCtx is a no-op", func(t *testing.T) {
		source, _ := url.Parse("http://example.com")
		recordRedirect(source, "http://other.com", nil)
		// Should not panic
	})

	t.Run("nil source is a no-op", func(t *testing.T) {
		reqCtx := &request.Context{}
		recordRedirect(nil, "http://other.com", reqCtx)
		assert.Empty(t, reqCtx.GetOutgoingRedirects())
	})

	t.Run("invalid location is a no-op", func(t *testing.T) {
		source, _ := url.Parse("http://example.com")
		reqCtx := &request.Context{}
		recordRedirect(source, "://invalid", reqCtx)
		assert.Empty(t, reqCtx.GetOutgoingRedirects())
	})

	t.Run("records absolute redirect", func(t *testing.T) {
		source, _ := url.Parse("http://example.com/path")
		reqCtx := &request.Context{}
		recordRedirect(source, "http://internal.host:8080/other", reqCtx)

		redirects := reqCtx.GetOutgoingRedirects()
		require.Len(t, redirects, 1)
		assert.Equal(t, "example.com", redirects[0].SourceHostname)
		assert.Equal(t, uint32(80), redirects[0].SourcePort)
		assert.Equal(t, "internal.host", redirects[0].DestHostname)
		assert.Equal(t, uint32(8080), redirects[0].DestPort)
	})

	t.Run("resolves relative redirect against source", func(t *testing.T) {
		source, _ := url.Parse("https://example.com/original")
		reqCtx := &request.Context{}
		recordRedirect(source, "/redirected", reqCtx)

		redirects := reqCtx.GetOutgoingRedirects()
		require.Len(t, redirects, 1)
		assert.Equal(t, "example.com", redirects[0].SourceHostname)
		assert.Equal(t, uint32(443), redirects[0].SourcePort)
		assert.Equal(t, "example.com", redirects[0].DestHostname)
		assert.Equal(t, uint32(443), redirects[0].DestPort)
	})

}

func TestRoundTrip_PropagatesInnerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close() // close immediately so transport fails

	transport := &ssrfTransport{inner: &http.Transport{}}
	req := httptest.NewRequest("GET", ts.URL, nil)
	resp, err := transport.RoundTrip(req)

	assert.Error(t, err)
	if resp != nil {
		resp.Body.Close()
	}
}

func TestRoundTrip_RecordsRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://internal.host:9090/target")
		w.WriteHeader(302)
	}))
	defer ts.Close()

	ctx := request.SetContext(context.TODO(), httptest.NewRequest("GET", "/test", nil), request.ContextData{
		Source: "test",
		Route:  "/test",
	})

	transport := &ssrfTransport{inner: &http.Transport{}}
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api", nil)
	resp, err := transport.RoundTrip(req)

	assert.NoError(t, err)
	resp.Body.Close()

	reqCtx := request.GetContext(ctx)
	redirects := reqCtx.GetOutgoingRedirects()
	require.Len(t, redirects, 1)
	assert.Equal(t, "internal.host", redirects[0].DestHostname)
	assert.Equal(t, uint32(9090), redirects[0].DestPort)
}

func TestRoundTrip_NonRedirectDoesNotRecord(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	ctx := request.SetContext(context.TODO(), httptest.NewRequest("GET", "/test", nil), request.ContextData{
		Source: "test",
		Route:  "/test",
	})

	transport := &ssrfTransport{inner: &http.Transport{}}
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api", nil)
	resp, err := transport.RoundTrip(req)

	assert.NoError(t, err)
	resp.Body.Close()

	reqCtx := request.GetContext(ctx)
	assert.Empty(t, reqCtx.GetOutgoingRedirects())
}

func TestIsRedirect(t *testing.T) {
	assert.True(t, isRedirect(301))
	assert.True(t, isRedirect(302))
	assert.False(t, isRedirect(200))
	assert.False(t, isRedirect(400))
}
