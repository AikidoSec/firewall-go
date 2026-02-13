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
