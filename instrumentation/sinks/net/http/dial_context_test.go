//go:build !integration

package http

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupProtection(t *testing.T) {
	t.Helper()
	originalDisabled := zen.IsDisabled()
	originalClient := agent.GetCloudClient()
	originalBlocking := config.IsBlockingEnabled()

	t.Cleanup(func() {
		zen.SetDisabled(originalDisabled)
		agent.SetCloudClient(originalClient)
		config.SetBlocking(originalBlocking)
	})

	require.NoError(t, zen.Protect())
	config.SetBlocking(true)
	agent.SetCloudClient(testutil.NewMockCloudClient())
}

// mockConn implements net.Conn with a configurable RemoteAddr.
type mockConn struct {
	net.Conn
	remoteAddr net.Addr
	closed     bool
}

func (c *mockConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *mockConn) Close() error         { c.closed = true; return nil }

func dialerReturning(remoteAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{remoteAddr: mockTCPAddr(remoteAddr)}, nil
	}
}

func mockTCPAddr(hostPort string) *net.TCPAddr {
	host, portStr, _ := net.SplitHostPort(hostPort)
	port, _ := net.LookupPort("tcp", portStr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func TestSsrfDialContext_BlocksLiteralPrivateIPFromUserInput(t *testing.T) {
	setupProtection(t)

	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2F10.0.0.1%2Finternal", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	original := dialerReturning("10.0.0.1:80")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "10.0.0.1:80")

	assert.Error(t, err, "should block literal private IP found in user input")
	assert.Nil(t, conn, "should not return a connection when blocked")
}

func TestSsrfDialContext_BlocksDNSResolvedPrivateIP(t *testing.T) {
	setupProtection(t)

	// "localhost" resolves to 127.0.0.1
	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2Flocalhost%2Finternal", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	// Simulate the real dialer resolving localhost to 127.0.0.1
	original := dialerReturning("127.0.0.1:80")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "localhost:80")

	assert.Error(t, err, "should block when connected IP is private and hostname is in user input")
	assert.Nil(t, conn, "should not return a connection when blocked")
}

func TestSsrfDialContext_ClosesConnectionOnBlock(t *testing.T) {
	setupProtection(t)

	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2F10.0.0.1%2Finternal", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	mc := &mockConn{remoteAddr: mockTCPAddr("10.0.0.1:80")}
	original := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return mc, nil
	}

	wrapped := ssrfDialContext(original)
	_, _ = wrapped(ctx, "tcp", "10.0.0.1:80")

	assert.True(t, mc.closed, "should close the connection when blocking")
}

// Reproduces QA test_ssrf: http://ⓛocalhost:4000/ should be blocked.
// The Unicode circled-L (U+24DB) gets NFKC-normalized to "l" by the OS/DNS resolver,
// so DialContext connects to 127.0.0.1. The SSRF check must catch this.
func TestSsrfDialContext_BlocksUnicodeConfusableLocalhost(t *testing.T) {
	setupProtection(t)

	// User sends URL with Unicode confusable hostname in query
	incomingReq := httptest.NewRequest("GET", "/api/request?url=http%3A%2F%2F%E2%93%9Bocalhost%3A4000%2F", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/api/request",
		RemoteAddress: &ip,
	})

	// Go's HTTP transport IDNA-normalizes ⓛocalhost → localhost before dialing.
	// DialContext receives "localhost:4000", which resolves to 127.0.0.1.
	original := dialerReturning("127.0.0.1:4000")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "localhost:4000")

	assert.Error(t, err, "should block Unicode confusable localhost that resolves to private IP")
	assert.Nil(t, conn, "should not return a connection when blocked")
}

func TestSsrfDialContext_AllowsPublicIP(t *testing.T) {
	setupProtection(t)

	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2Fexample.com", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	original := dialerReturning("93.184.216.34:80")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "example.com:80")

	assert.NoError(t, err, "should allow hostname that resolves to public IP")
	assert.NotNil(t, conn, "should return the connection")
}

// Reproduces QA test_ssrf_diffrent_port: body contains url=http://127.0.0.1:4001
// and port=4000, server changes the port and connects to 127.0.0.1:4000.
// Should NOT be blocked because the user-supplied port (4001) differs from
// the actual connection port (4000).
func TestSsrfDialContext_AllowsDifferentPortThanUserInput(t *testing.T) {
	setupProtection(t)

	// Simulate POST body: url=http://127.0.0.1:4001&port=4000
	incomingReq := httptest.NewRequest("POST", "/api/request_different_port",
		strings.NewReader("url=http%3A%2F%2F127.0.0.1%3A4001&port=4000"))
	incomingReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/api/request_different_port",
		RemoteAddress: &ip,
	})

	// Server rewrites URL to use port 4000, connects to 127.0.0.1:4000
	original := dialerReturning("127.0.0.1:4000")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "127.0.0.1:4000")

	assert.NoError(t, err, "should not block when server changes the port from user input")
	assert.NotNil(t, conn, "should return the connection")
}

// Reproduces QA test_ssrf: http://ssrf-redirects.testssandbox.com/ssrf-test-4
// redirects to a private IP. The redirect origin hostname IS in user input,
// so the request to the private IP should be blocked.
func TestSsrfDialContext_BlocksRedirectToPrivateIP(t *testing.T) {
	setupProtection(t)

	// User sends the redirect hostname in query params
	incomingReq := httptest.NewRequest("GET",
		"/api/request?url=http%3A%2F%2Fssrf-redirects.testssandbox.com%2Fssrf-test-4", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/api/request",
		RemoteAddress: &ip,
	})

	// Simulate the redirect chain: RoundTrip recorded that
	// ssrf-redirects.testssandbox.com:80 redirected to 127.0.0.1:4000
	reqCtx := request.GetContext(ctx)
	reqCtx.AddOutgoingRedirect(request.RedirectEntry{
		SourceHostname: "ssrf-redirects.testssandbox.com",
		SourcePort:     80,
		DestHostname:   "127.0.0.1",
		DestPort:       4000,
	})

	// DialContext is called for the redirect target
	original := dialerReturning("127.0.0.1:4000")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "127.0.0.1:4000")

	assert.Error(t, err, "should block redirect to private IP when origin hostname is in user input")
	assert.Nil(t, conn, "should not return a connection when blocked")
}

func TestSsrfDialContext_PropagatesDialError(t *testing.T) {
	setupProtection(t)

	ctx := context.Background()
	dialErr := errors.New("connection refused")
	original := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, dialErr
	}

	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "example.com:80")

	assert.ErrorIs(t, err, dialErr)
	assert.Nil(t, conn)
}

func TestSsrfDialContext_HandlesInvalidAddr(t *testing.T) {
	setupProtection(t)

	ctx := context.Background()
	original := dialerReturning("93.184.216.34:80")
	wrapped := ssrfDialContext(original)

	// addr without port — SplitHostPort fails, should return conn without error
	conn, err := wrapped(ctx, "tcp", "no-port")

	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

// mockStringAddr implements net.Addr with a custom string representation.
type mockStringAddr string

func (a mockStringAddr) Network() string { return "tcp" }
func (a mockStringAddr) String() string  { return string(a) }

func TestSsrfDialContext_HandlesInvalidRemoteAddr(t *testing.T) {
	setupProtection(t)

	ctx := context.Background()
	original := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{remoteAddr: mockStringAddr("not-host-port")}, nil
	}

	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "example.com:80")

	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestSsrfDialContext_AllowsWhenNoRequestContext(t *testing.T) {
	setupProtection(t)

	// Without request context, regular private IPs are allowed (only IMDS IPs are blocked)
	ctx := context.Background()
	original := dialerReturning("10.0.0.1:80")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "10.0.0.1:80")

	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestStoredSsrf(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		remoteAddr string
		useReqCtx  bool
		wantBlock  bool
	}{
		{"blocks IMDS IP with request context", "evil.com", "169.254.169.254:80", true, true},
		{"blocks IMDS IP without request context", "evil.com", "169.254.169.254:80", false, true},
		{"allows trusted hostname", "metadata.google.internal", "169.254.169.254:80", false, false},
		{"allows IP literal matching IMDS", "169.254.169.254", "169.254.169.254:80", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupProtection(t)

			var ctx context.Context
			if tt.useReqCtx {
				incomingReq := httptest.NewRequest("GET", "/test", nil)
				ip := "1.2.3.4"
				ctx = request.SetContext(context.Background(), incomingReq, request.ContextData{
					Source:        "test",
					Route:         "/test",
					RemoteAddress: &ip,
				})
			} else {
				ctx = context.Background()
			}

			original := dialerReturning(tt.remoteAddr)
			wrapped := ssrfDialContext(original)
			conn, err := wrapped(ctx, "tcp", tt.hostname+":80")

			if tt.wantBlock {
				assert.Error(t, err)
				assert.Nil(t, conn)
				var attackErr *zen.AttackBlockedError
				require.True(t, errors.As(err, &attackErr))
				assert.Equal(t, vulnerabilities.KindStoredSSRF, attackErr.Kind)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conn)
			}
		})
	}

	t.Run("closes connection on block", func(t *testing.T) {
		setupProtection(t)

		mc := &mockConn{remoteAddr: mockTCPAddr("169.254.169.254:80")}
		original := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return mc, nil
		}

		wrapped := ssrfDialContext(original)
		_, _ = wrapped(context.Background(), "tcp", "evil.com:80")

		assert.True(t, mc.closed)
	})
}

func TestSsrfDialContext_AllowsPrivateIPNotInUserInput(t *testing.T) {
	setupProtection(t)

	// User input contains a different hostname
	incomingReq := httptest.NewRequest("GET", "/test?url=http%3A%2F%2Fexample.com", nil)
	ip := "1.2.3.4"
	ctx := request.SetContext(context.Background(), incomingReq, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
	})

	original := dialerReturning("10.0.0.1:80")
	wrapped := ssrfDialContext(original)
	conn, err := wrapped(ctx, "tcp", "10.0.0.1:80")

	assert.NoError(t, err, "should allow private IP not originating from user input")
	assert.NotNil(t, conn, "should return the connection")
}
