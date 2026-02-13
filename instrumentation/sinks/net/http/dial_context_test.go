//go:build !integration

package http

import (
	"context"
	"net"
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
