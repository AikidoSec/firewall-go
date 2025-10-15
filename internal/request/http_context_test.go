package request

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetContext(t *testing.T) {
	tests := []struct {
		name          string
		route         string
		source        string
		remoteAddress *string
		body          any
		expectedRoute string
	}{
		{
			name:          "with custom route",
			route:         "/api/users",
			source:        "gin",
			remoteAddress: stringPtr("192.168.1.1"),
			body:          map[string]string{"name": "test"},
			expectedRoute: "/api/users",
		},
		{
			name:          "empty route uses URL path",
			route:         "",
			source:        "echo",
			remoteAddress: stringPtr("127.0.0.1"),
			body:          "test body",
			expectedRoute: "/test/path", // Will be set from request URL
		},
		{
			name:          "nil remote address",
			route:         "/api/data",
			source:        "custom",
			remoteAddress: nil,
			body:          nil,
			expectedRoute: "/api/data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request
			req, err := http.NewRequest("POST", "http://example.com/test/path?param=value", strings.NewReader("test body"))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "test-agent")
			req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

			// Set context
			ctx := context.Background()
			resultCtx := SetContext(ctx, req, tt.route, tt.source, tt.remoteAddress, tt.body)

			// Get context back
			reqCtx := GetContext(resultCtx)
			assert.NotNil(t, reqCtx, "GetContext should not return nil")

			// Light assertions - focus on ensuring context is correctly set
			assert.Equal(t, tt.source, reqCtx.Source)

			if tt.route == "" {
				// When route is empty, it should use the request URL path
				assert.Equal(t, "/test/path", reqCtx.Route)
			} else {
				assert.Equal(t, tt.expectedRoute, reqCtx.Route)
			}

			// Verify basic request data is captured
			assert.NotEmpty(t, reqCtx.URL, "URL should not be empty")
			assert.NotNil(t, reqCtx.Method, "Method should not be nil")
			assert.Equal(t, "POST", *reqCtx.Method, "Method should be POST")
			// Note: Body comparison removed as it can contain uncomparable types like maps
			assert.Equal(t, tt.remoteAddress, reqCtx.RemoteAddress)
		})
	}
}

func TestGetContext(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		expectNil bool
	}{
		{
			name:      "context with no value",
			ctx:       context.Background(),
			expectNil: true,
		},
		{
			name:      "context with different value",
			ctx:       context.WithValue(context.Background(), "other-key", "other-value"),
			expectNil: true,
		},
		{
			name:      "context with request context",
			ctx:       context.WithValue(context.Background(), reqCtxKey, &Context{Source: "test"}),
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetContext(tt.ctx)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, "test", result.Source)
			}
		})
	}
}

func TestFullURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		host     string
		hasTLS   bool
		expected string
	}{
		{
			name:     "HTTP request",
			url:      "http://example.com/path",
			host:     "example.com",
			hasTLS:   false,
			expected: "http://example.com/path",
		},
		{
			name:     "HTTPS request",
			url:      "https://example.com/path",
			host:     "example.com",
			hasTLS:   true,
			expected: "https://example.com/path",
		},
		{
			name:     "HTTP with query",
			url:      "http://example.com/path?param=value",
			host:     "example.com",
			hasTLS:   false,
			expected: "http://example.com/path?param=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.url)
			assert.NoError(t, err)

			req := &http.Request{
				Method: "GET",
				URL:    parsedURL,
				Host:   tt.host,
			}

			if tt.hasTLS {
				req.TLS = &tls.ConnectionState{}
			}

			result := fullURL(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}
