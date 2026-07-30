package request

import (
	"context"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testContextKey struct{}

var testCtxKey = testContextKey{}

func TestSetContext(t *testing.T) {
	tests := []struct {
		name          string
		route         string
		routeParams   map[string]string
		source        string
		remoteAddress *string
		body          any
		expectedRoute string
		expectedPath  string
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
			expectedRoute: "/test/path", // Will be set from path
		},
		{
			name:          "nil remote address",
			route:         "/api/data",
			source:        "custom",
			remoteAddress: nil,
			body:          nil,
			expectedRoute: "/api/data",
		},
		{
			name:          "route params",
			route:         "/test/path",
			source:        "test",
			remoteAddress: stringPtr("127.0.0.1"),
			body:          "test body",
			routeParams: map[string]string{
				"user": "1234",
				"role": "test",
			},
			expectedRoute: "/test/path",
		},
		{
			name:          "trim trailing slash",
			route:         "/test/slash/",
			source:        "test",
			expectedRoute: "/test/slash",
		},
		{
			name:          "don't trim root slash",
			route:         "/",
			source:        "test",
			expectedRoute: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			resultCtx := SetContext(ctx, ContextData{
				Source:        tt.source,
				Route:         tt.route,
				RouteParams:   tt.routeParams,
				RemoteAddress: tt.remoteAddress,
				Body:          tt.body,
				URL:           "http://example.com/test/path?param=value",
				Path:          "/test/path",
				Method:        "POST",
				Query:         map[string][]string{"param": {"value"}},
				Headers:       map[string][]string{"content-type": {"application/json"}, "user-agent": {"test-agent"}},
				Cookies:       map[string][]string{"session": {"abc123"}},
			})

			reqCtx := GetContext(resultCtx)
			assert.NotNil(t, reqCtx, "GetContext should not return nil")

			assert.Equal(t, tt.source, reqCtx.Source)

			if tt.route == "" {
				assert.Equal(t, "/test/path", reqCtx.Route)
			} else {
				assert.Equal(t, tt.expectedRoute, reqCtx.Route)
			}

			assert.Equal(t, "/test/path", reqCtx.Path)

			assert.Equal(t, tt.routeParams, reqCtx.RouteParams)

			assert.NotEmpty(t, reqCtx.URL, "URL should not be empty")
			assert.NotNil(t, reqCtx.Method, "Method should not be nil")
			assert.Equal(t, "POST", reqCtx.Method, "Method should be POST")
			assert.Equal(t, tt.remoteAddress, reqCtx.RemoteAddress)
		})
	}
}

func TestSetContext_DuplicateCookies(t *testing.T) {
	resultCtx := SetContext(context.Background(), ContextData{
		Source:  "test",
		Cookies: map[string][]string{"session": {"first", "second"}},
	})
	reqCtx := GetContext(resultCtx)

	assert.Equal(t, []string{"first", "second"}, reqCtx.Cookies["session"])
}

func TestSetContext_BypassedIP(t *testing.T) {
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		BypassedIPs: []string{"10.10.10.10"},
		Block:       &block,
	}, nil)

	ctx := context.Background()
	ip := "10.10.10.10"
	setCtx := SetContext(ctx, ContextData{
		RemoteAddress: &ip,
	})

	require.NotNil(t, setCtx)

	result := GetContext(setCtx)
	require.Nil(t, result)
	assert.True(t, IsBypassed(setCtx))
}

func TestIsBypassed(t *testing.T) {
	t.Run("returns false for nil context", func(t *testing.T) {
		//nolint:staticcheck // We want to test the nil case
		assert.False(t, IsBypassed(nil))
	})

	t.Run("returns false for context without bypass flag", func(t *testing.T) {
		assert.False(t, IsBypassed(context.Background()))
	})

	t.Run("falls back to GLS when context is nil", func(t *testing.T) {
		block := true
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{
			BypassedIPs: []string{"10.10.10.10"},
			Block:       &block,
		}, nil)

		ip := "10.10.10.10"
		bypassedCtx := SetContext(context.Background(), ContextData{RemoteAddress: &ip})
		require.True(t, IsBypassed(bypassedCtx))

		var result bool
		WrapWithGLS(bypassedCtx, func() {
			//nolint:staticcheck // We want to test the nil case
			result = IsBypassed(nil)
		})
		assert.True(t, result)
	})

	t.Run("falls back to GLS when context has no bypass flag", func(t *testing.T) {
		block := true
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{
			BypassedIPs: []string{"10.10.10.10"},
			Block:       &block,
		}, nil)

		ip := "10.10.10.10"
		bypassedCtx := SetContext(context.Background(), ContextData{RemoteAddress: &ip})
		require.True(t, IsBypassed(bypassedCtx))

		var result bool
		WrapWithGLS(bypassedCtx, func() {
			result = IsBypassed(context.Background())
		})
		assert.True(t, result)
	})
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
			ctx:       context.WithValue(context.Background(), testCtxKey, "other-value"),
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

func TestEnsureContextPropagated(t *testing.T) {
	t.Run("returns same context when request data already present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), reqCtxKey, &Context{Source: "test"})
		result := EnsureContextPropagated(ctx)
		assert.Same(t, ctx, result, "should return the same context unchanged")
	})

	t.Run("copies GLS data into context", func(t *testing.T) {
		ip := "1.2.3.4"
		glsCtx := SetContext(context.Background(), ContextData{
			Source:        "test-source",
			Route:         "/test",
			RemoteAddress: &ip,
		})

		WrapWithGLS(glsCtx, func() {
			bare := context.Background()
			result := EnsureContextPropagated(bare)

			reqCtx := GetContext(result)
			require.NotNil(t, reqCtx)
			assert.Equal(t, "test-source", reqCtx.Source)
			assert.Equal(t, "/test", reqCtx.Route)
		})
	})

	t.Run("returns same context when no GLS and no request data", func(t *testing.T) {
		ctx := context.Background()
		result := EnsureContextPropagated(ctx)
		assert.Nil(t, GetContext(result), "should have no request context")
	})

	t.Run("copies bypassed flag from GLS into bare context", func(t *testing.T) {
		block := true
		config.UpdateServiceConfig(&aikido_types.CloudConfigData{
			BypassedIPs: []string{"10.10.10.10"},
			Block:       &block,
		}, nil)

		ip := "10.10.10.10"
		bypassedCtx := SetContext(context.Background(), ContextData{RemoteAddress: &ip})
		require.True(t, IsBypassed(bypassedCtx))

		WrapWithGLS(bypassedCtx, func() {
			result := EnsureContextPropagated(context.Background())
			assert.True(t, IsBypassed(result), "should propagate bypass flag from GLS into bare context")
		})
	})
}
