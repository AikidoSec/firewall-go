package request

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapWithGLS(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantNil  bool
	}{
		{
			name: "context with request context",
			setupCtx: func() context.Context {
				req, _ := http.NewRequest("GET", "https://example.com/test", nil)
				req.Header.Set("User-Agent", "test-agent")
				req.RemoteAddr = "192.168.1.1:8080"

				ctx := context.Background()
				return SetContext(ctx, req, ContextData{
					Source:        "test-source",
					Route:         "/test",
					RemoteAddress: &req.RemoteAddr,
				})
			},
			wantNil: false,
		},
		{
			name:     "context without request context",
			setupCtx: context.Background,
			wantNil:  true,
		},
		{
			name: "nil context",
			setupCtx: func() context.Context {
				return nil
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()

			var capturedCtx *Context

			// Wrap the function with GLS
			WrapWithGLS(ctx, func() {
				// Inside the wrapped function, get the local context
				capturedCtx = getLocalContext()
			})

			if tt.wantNil {
				assert.Nil(t, capturedCtx, "WrapWithGLS() should capture nil context")
			} else {
				require.NotNil(t, capturedCtx, "WrapWithGLS() should capture non-nil context")

				// Verify the context was properly propagated
				originalCtx := GetContext(ctx)
				require.NotNil(t, originalCtx, "GetContext() should return non-nil")

				// Compare key fields to ensure they match
				assert.Equal(t, originalCtx.URL, capturedCtx.URL, "URL should match")
				assert.Equal(t, originalCtx.Source, capturedCtx.Source, "Source should match")
				assert.Equal(t, originalCtx.Route, capturedCtx.Route, "Route should match")
				assert.Equal(t, originalCtx.Method, capturedCtx.Method, "Method should match")
			}
		})
	}
}

func TestGetLocalContext_WithoutWrap(t *testing.T) {
	// Test that getLocalContext returns nil when not wrapped
	ctx := getLocalContext()
	assert.Nil(t, ctx, "getLocalContext() should return nil when not wrapped")
}

func TestWrapWithGLS_ConcurrentAccess(t *testing.T) {
	// Test that GLS works correctly with concurrent goroutines
	const numGoroutines = 5
	blockers := make([]chan struct{}, numGoroutines)
	results := make(chan *Context, numGoroutines)

	// Create different contexts for each goroutine
	for i := 0; i < numGoroutines; i++ {
		blockers[i] = make(chan struct{})

		go func(id int) {
			req, _ := http.NewRequest("GET", fmt.Sprintf("https://example.com/req%d", id), nil)
			req.RemoteAddr = fmt.Sprintf("192.168.1.%d:8080", id)
			ctx := SetContext(context.Background(), req, ContextData{
				Source:        fmt.Sprintf("source%d", id),
				Route:         fmt.Sprintf("/req%d", id),
				RemoteAddress: &req.RemoteAddr,
			})

			WrapWithGLS(ctx, func() {
				// Block here until we're told to proceed
				<-blockers[id]

				// Now get the local context
				captured := getLocalContext()
				results <- captured
			})
		}(i)
	}

	// Unblock one by one and verify each gets the correct context
	for i := 0; i < numGoroutines; i++ {
		// Unblock this goroutine
		close(blockers[i])

		// Get its result
		ctx := <-results
		require.NotNil(t, ctx, "Expected context to be non-nil")

		// Verify it has the correct data for this goroutine
		expectedURL := fmt.Sprintf("http://example.com/req%d", i)
		expectedSource := fmt.Sprintf("source%d", i)
		expectedRoute := fmt.Sprintf("/req%d", i)

		assert.Equal(t, expectedURL, ctx.URL, "URL should match for goroutine %d", i)
		assert.Equal(t, expectedSource, ctx.Source, "Source should match for goroutine %d", i)
		assert.Equal(t, expectedRoute, ctx.Route, "Route should match for goroutine %d", i)
		assert.Equal(t, "GET", ctx.Method, "Method should be GET")
	}
}
