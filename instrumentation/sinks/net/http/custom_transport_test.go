//go:build !integration

package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/testutil"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A function-valued RoundTripper also guards against caching arbitrary custom
// transports as map keys: not every RoundTripper is comparable.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// Models an SDK transport that calls the underlying transport directly,
// without going through http.Client.transport again.
type forwardingTransport struct {
	inner http.RoundTripper
}

func (t *forwardingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req)
}

func protectCustomTransportTest(t *testing.T) {
	t.Helper()

	originalDisabled := zen.IsDisabled()
	t.Cleanup(func() { zen.SetDisabled(originalDisabled) })
	require.NoError(t, zen.Protect())

	originalClient := agent.GetCloudClient()
	t.Cleanup(func() { agent.SetCloudClient(originalClient) })
	agent.SetCloudClient(testutil.NewMockCloudClient())
	require.True(t, zen.ShouldProtect())
}

func TestWrapTransport_CustomTransport_PropagatesContext(t *testing.T) {
	protectCustomTransportTest(t)

	ctx := request.SetContext(context.Background(), request.ContextData{Source: "test", Route: "/test"})
	expected := request.GetContext(ctx)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)
	originalContext := req.Context()
	var received *http.Request
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		received = req

		// Transport dialers run in another goroutine, where GLS is unavailable.
		captured := make(chan *request.Context, 1)
		go func() { captured <- request.GetContext(req.Context()) }()
		assert.Same(t, expected, <-captured, "request context must reach transport goroutines")
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	request.WrapWithGLS(ctx, func() {
		resp, err := WrapTransport(rt).RoundTrip(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		resp.Body.Close()
	})

	require.NotNil(t, received)
	assert.NotSame(t, req, received, "context propagation must not mutate the caller's request")
	assert.True(t, originalContext == req.Context(), "the caller's context must stay unchanged")
}

func TestWrapTransport_CustomTransport_RecordsRedirectChain(t *testing.T) {
	protectCustomTransportTest(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
		case "/next":
			w.Header().Set("Location", "/end")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/end":
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	inner := &http.Transport{}
	defer inner.CloseIdleConnections()
	client := &http.Client{Transport: WrapTransport(&forwardingTransport{inner: inner})}
	ctx := request.SetContext(context.Background(), request.ContextData{Source: "test", Route: "/test"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/start", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))

	redirects := request.GetContext(ctx).GetOutgoingRedirects()
	require.Len(t, redirects, 2, "SDK-style forwarding transports must not bypass redirect tracking")
	for _, redirect := range redirects {
		assert.Equal(t, req.URL.Hostname(), redirect.SourceHostname)
		assert.Equal(t, portFromURL(req.URL), redirect.SourcePort)
		assert.Equal(t, req.URL.Hostname(), redirect.DestHostname)
		assert.Equal(t, portFromURL(req.URL), redirect.DestPort)
	}
}

func TestWrapTransport_CustomTransport_NonFollowedStatusDoesNotRecordRedirect(t *testing.T) {
	protectCustomTransportTest(t)

	for _, status := range []int{
		http.StatusMultipleChoices,
		http.StatusNotModified,
		http.StatusUseProxy,
		306,
		399,
	} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			ctx := request.SetContext(context.Background(), request.ContextData{Source: "test"})
			calls := 0
			rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Location": {"https://internal.example/target"}},
					Body:       http.NoBody,
				}, nil
			})
			client := &http.Client{Transport: WrapTransport(rt)}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://user-controlled.example/start", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, status, resp.StatusCode)
			assert.Equal(t, 1, calls, "net/http must not follow this response")
			assert.Empty(t, request.GetContext(ctx).GetOutgoingRedirects(), "non-followed statuses must not contaminate later SSRF checks")
		})
	}
}

func TestWrapTransport_CustomTransport_PreservesResponseAndError(t *testing.T) {
	protectCustomTransportTest(t)

	innerErr := errors.New("origin rejected")
	for _, tc := range []struct {
		name string
		resp *http.Response
		err  error
	}{
		{
			name: "response",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Origin": {"sdk"}},
				Body:       io.NopCloser(strings.NewReader("unchanged")),
			},
		},
		{name: "error", err: innerErr},
		{name: "nil response without error"},
		{
			name: "response with error",
			resp: &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": {"/next"}},
				Body:       http.NoBody,
			},
			err: innerErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := request.SetContext(context.Background(), request.ContextData{Source: "test"})
			req := httptest.NewRequest(http.MethodPost, "https://example.com/api", strings.NewReader(`{"prompt":"hello"}`)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer test-token")
			req.Header.Set("Content-Type", "application/json")
			calls := 0
			rt := roundTripperFunc(func(received *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, req.Method, received.Method)
				assert.Equal(t, req.URL, received.URL)
				assert.Equal(t, req.Header, received.Header)
				assert.True(t, req.Body == received.Body, "preserve the SDK's request body")
				assert.Same(t, request.GetContext(ctx), request.GetContext(received.Context()))
				return tc.resp, tc.err
			})

			resp, err := WrapTransport(rt).RoundTrip(req)
			assert.Equal(t, 1, calls)
			assert.True(t, err == tc.err, "preserve the original error")
			assert.Same(t, tc.resp, resp)
			assert.Empty(t, request.GetContext(ctx).GetOutgoingRedirects())
			if resp != nil {
				defer resp.Body.Close()
				if tc.err == nil {
					body, readErr := io.ReadAll(resp.Body)
					require.NoError(t, readErr)
					assert.Equal(t, "unchanged", string(body))
				}
			}
		})
	}
}

type observedBody struct {
	reader io.Reader
	reads  int
	closes int
}

func (b *observedBody) Read(p []byte) (int, error) {
	b.reads++
	return b.reader.Read(p)
}

func (b *observedBody) Close() error {
	b.closes++
	return nil
}

func TestWrapTransport_CustomTransport_DoesNotReadOrCloseBody(t *testing.T) {
	protectCustomTransportTest(t)

	body := &observedBody{reader: strings.NewReader("streamed response")}
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)
	resp, err := WrapTransport(rt).RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	t.Cleanup(func() {
		if body.closes == 0 {
			resp.Body.Close()
		}
	})

	assert.Zero(t, body.reads, "RoundTrip must not eagerly consume streaming responses")
	assert.Zero(t, body.closes, "the caller owns the response body")

	contents, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "streamed response", string(contents))
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, 1, body.closes, "closing the returned body must close the underlying body")
}

func TestWrapTransport_CustomTransport_PreservesContextSemantics(t *testing.T) {
	protectCustomTransportTest(t)

	type contextKey struct{}
	glsCtx := request.SetContext(context.Background(), request.ContextData{Source: "test"})

	for _, tc := range []struct {
		name     string
		deadline time.Time
	}{
		{name: "cancellation"},
		{name: "deadline", deadline: time.Now().Add(time.Hour)},
		{name: "expired deadline", deadline: time.Now().Add(-time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), contextKey{}, "caller value")
			var cancel context.CancelFunc
			if tc.deadline.IsZero() {
				ctx, cancel = context.WithCancel(ctx)
			} else {
				ctx, cancel = context.WithDeadline(ctx, tc.deadline)
			}
			defer cancel()

			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, "caller value", req.Context().Value(contextKey{}))
				deadline, ok := req.Context().Deadline()
				assert.Equal(t, !tc.deadline.IsZero(), ok)
				assert.Equal(t, tc.deadline, deadline)
				assert.True(t, ctx.Done() == req.Context().Done(), "preserve the caller's cancellation channel")

				cancel()
				assert.Equal(t, ctx.Err(), req.Context().Err())
				return nil, req.Context().Err()
			})
			req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil).WithContext(ctx)

			// Force the wrapper to derive a context from the caller's context.
			request.WrapWithGLS(glsCtx, func() {
				resp, err := WrapTransport(rt).RoundTrip(req)
				assert.Nil(t, resp)
				assert.ErrorIs(t, err, ctx.Err())
			})
		})
	}
}

type idleClosingTransport struct {
	closes int
}

func (t *idleClosingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func (t *idleClosingTransport) CloseIdleConnections() {
	t.closes++
}

func TestWrapTransport_CustomTransport_ForwardsCloseIdleConnections(t *testing.T) {
	protectCustomTransportTest(t)

	rt := &idleClosingTransport{}
	client := &http.Client{Transport: WrapTransport(rt)}
	client.CloseIdleConnections()
	assert.Equal(t, 1, rt.closes, "wrapping must not hide optional transport cleanup")

	client.Transport = WrapTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))
	assert.NotPanics(t, client.CloseIdleConnections, "cleanup remains a no-op when the inner transport does not support it")
}
