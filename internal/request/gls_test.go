package request

import (
	"context"
	"fmt"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
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
				remoteAddr := "192.168.1.1:8080"
				ctx := context.Background()
				return SetContext(ctx, ContextData{
					Source:        "test-source",
					Route:         "/test",
					RemoteAddress: &remoteAddr,
					URL:           "https://example.com/test",
					Path:          "/test",
					Method:        "GET",
					Headers:       map[string][]string{"user-agent": {"test-agent"}},
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

func TestEnterGLS(t *testing.T) {
	remoteAddr := "192.168.1.1:8080"
	ctx := SetContext(context.Background(), ContextData{
		Source:        "test-source",
		Route:         "/test",
		RemoteAddress: &remoteAddr,
		URL:           "https://example.com/test",
		Path:          "/test",
		Method:        "GET",
	})

	assert.Nil(t, getLocalContext(), "GLS should be empty before EnterGLS is called")

	restore := EnterGLS(ctx)

	captured := getLocalContext()
	require.NotNil(t, captured, "context should be visible via GLS as soon as EnterGLS returns, without needing a wrapping closure")
	assert.Equal(t, "test-source", captured.Source)

	restore()

	assert.Nil(t, getLocalContext(), "GLS should be restored to its previous state once restore is called")
}

func TestEnterScan(t *testing.T) {
	assert.False(t, IsScanning(), "should not be scanning before EnterScan is called")

	restore := EnterScan()
	assert.True(t, IsScanning(), "should be scanning as soon as EnterScan returns")

	restore()
	assert.False(t, IsScanning(), "should be restored to its previous state once restore is called")
}

func TestEnterScan_Nested(t *testing.T) {
	outer := EnterScan()
	inner := EnterScan()

	inner()
	assert.True(t, IsScanning(), "outer scan should still be marked once the inner one restores")

	outer()
	assert.False(t, IsScanning())
}

func TestEnterScan_PreservesRequestContext(t *testing.T) {
	remoteAddr := "192.168.1.1:8080"
	ctx := SetContext(context.Background(), ContextData{
		Source:        "test-source",
		Route:         "/test",
		RemoteAddress: &remoteAddr,
	})

	restoreGLS := EnterGLS(ctx)
	defer restoreGLS()

	restore := EnterScan()
	defer restore()

	captured := getLocalContext()
	require.NotNil(t, captured, "request context must stay visible to the scan that is running")
	assert.Equal(t, "test-source", captured.Source)
}

func TestEnterScan_ScopedToGoroutine(t *testing.T) {
	restore := EnterScan()
	defer restore()

	scanningElsewhere := make(chan bool, 1)
	go func() {
		scanningElsewhere <- IsScanning()
	}()

	assert.False(t, <-scanningElsewhere, "one goroutine scanning must not suppress scans on another")
}

func TestWrapWithGLS_BypassedContext(t *testing.T) {
	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		BypassedIPs: []string{"10.10.10.10"},
		Block:       &block,
	}, nil)

	ip := "10.10.10.10"
	ctx := SetContext(context.Background(), ContextData{RemoteAddress: &ip})
	require.True(t, IsBypassed(ctx))

	var capturedBypassed bool
	WrapWithGLS(ctx, func() {
		capturedBypassed = isLocalBypassed()
	})

	assert.True(t, capturedBypassed, "WrapWithGLS should store bypass flag in GLS for bypassed context")
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
			remoteAddr := fmt.Sprintf("192.168.1.%d:8080", id)
			ctx := SetContext(context.Background(), ContextData{
				Source:        fmt.Sprintf("source%d", id),
				Route:         fmt.Sprintf("/req%d", id),
				RemoteAddress: &remoteAddr,
				URL:           fmt.Sprintf("http://example.com/req%d", id),
				Path:          fmt.Sprintf("/req%d", id),
				Method:        "GET",
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
