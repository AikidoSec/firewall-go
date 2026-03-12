package vulnerabilities

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set zen as loaded for all tests in this package
	original := config.IsZenLoaded()
	config.SetZenLoaded(true)

	code := m.Run()

	config.SetZenLoaded(original)
	os.Exit(code)
}

// mockScanArgs is a simple type for testing
type mockScanArgs struct {
	Value string
}

// mockVulnerability is a mock vulnerability for testing
var mockVulnerability = Vulnerability[mockScanArgs]{
	ScanFunction: func(input string, args mockScanArgs) (*ScanResult, error) {
		// Detect attack if input contains "attack"
		if input == "attack" {
			return &ScanResult{
				DetectedAttack: true,
				Metadata:       map[string]string{"test": "metadata"},
			}, nil
		}
		return &ScanResult{DetectedAttack: false}, nil
	},
	Kind:  KindSQLInjection,
	Error: "",
}

func TestScanWithOptions_AllSourcesChecked(t *testing.T) {
	ip := "127.0.0.1"
	args := mockScanArgs{Value: "test"}

	// Enable blocking for tests that expect errors
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer config.SetBlocking(original)

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		body        any
		routeParams map[string]string
		expectError bool
		description string
	}{
		{
			name: "query parameters are scanned",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test?param1=attack&param2=safe", http.NoBody)
			},
			body:        nil,
			expectError: true,
			description: "query parameters should be scanned",
		},
		{
			name: "headers are scanned",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("X-Custom-Header", "attack")
				return req
			},
			body:        nil,
			expectError: true,
			description: "headers should be scanned",
		},
		{
			name: "cookies are scanned",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.AddCookie(&http.Cookie{Name: "session", Value: "attack"})
				return req
			},
			body:        nil,
			expectError: true,
			description: "cookies should be scanned",
		},
		{
			name: "route params are scanned",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody)
			},
			body:        nil,
			routeParams: map[string]string{"id": "attack"},
			expectError: true,
			description: "routeParams should be scanned",
		},
		{
			name: "body is scanned - string",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", http.NoBody)
			},
			body:        "attack",
			expectError: true,
			description: "body string should be scanned",
		},
		{
			name: "body is scanned - map",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", http.NoBody)
			},
			body:        map[string]any{"field": "attack"},
			expectError: true,
			description: "body map should be scanned",
		},
		{
			name: "body is scanned - nested map",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", http.NoBody)
			},
			body: map[string]any{
				"user": map[string]any{
					"name": "attack",
				},
			},
			expectError: true,
			description: "body nested map should be scanned",
		},
		{
			name: "body is scanned - array",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", http.NoBody)
			},
			body:        []any{"attack", "safe"},
			expectError: true,
			description: "body array should be scanned",
		},
		{
			name: "query with multiple values per key",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test?param=value1&param=value2&param=attack", http.NoBody)
			},
			body:        nil,
			expectError: true,
			description: "query parameters with multiple values should be scanned",
		},
		{
			name: "headers with multiple values",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Add("X-Header", "value1")
				req.Header.Add("X-Header", "attack")
				return req
			},
			body:        nil,
			expectError: true,
			description: "headers with multiple values should be scanned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/test",
				RemoteAddress: &ip,
				RouteParams:   tt.routeParams,
				Body:          tt.body,
			})

			err := ScanWithOptions(ctx, "testOperation", mockVulnerability, args, ScanOptions{})
			if tt.expectError {
				require.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), "SQL injection")
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestScanWithOptions_AllSourcesScannedWhenNoAttack(t *testing.T) {
	ip := "127.0.0.1"
	args := mockScanArgs{Value: "test"}

	// Track which sources were scanned by using unique marker values for each source
	scannedInputs := make(map[string]bool)
	trackingVuln := Vulnerability[mockScanArgs]{
		ScanFunction: func(input string, args mockScanArgs) (*ScanResult, error) {
			// Track that scanning occurred (input will be from various sources)
			scannedInputs[input] = true
			return &ScanResult{DetectedAttack: false}, nil
		},
		Kind:  KindSQLInjection,
		Error: "",
	}

	// Use unique values for each source to verify they're all scanned
	req := httptest.NewRequest("GET", "/test?queryParam=queryValue", http.NoBody)
	req.Header.Set("X-Header", "headerValue")
	req.AddCookie(&http.Cookie{Name: "cookie1", Value: "cookieValue"})
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
		RouteParams:   map[string]string{"routeParam": "routeValue"},
		Body:          map[string]any{"bodyField": "bodyValue"},
	})

	err := ScanWithOptions(ctx, "testOperation", trackingVuln, args, ScanOptions{})
	assert.NoError(t, err)

	// Verify all sources were scanned by checking that values from each source appear
	// Note: extractStringsFromUserInput extracts both keys and values from maps
	assert.True(t, scannedInputs["queryValue"], "query parameters should be scanned")
	assert.True(t, scannedInputs["headerValue"], "headers should be scanned")
	assert.True(t, scannedInputs["cookieValue"], "cookies should be scanned")
	assert.True(t, scannedInputs["routeValue"], "routeParams should be scanned")
	assert.True(t, scannedInputs["bodyValue"], "body should be scanned")
}

func TestScanWithOptions_NilContext(t *testing.T) {
	args := mockScanArgs{Value: "test"}
	ctx := context.Background()
	err := ScanWithOptions(ctx, "testOperation", mockVulnerability, args, ScanOptions{})
	assert.NoError(t, err)
}

func TestScanWithOptions_ForceProtectionOff(t *testing.T) {
	ip := "127.0.0.1"
	args := mockScanArgs{Value: "test"}

	// Enable blocking for tests that expect errors
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer config.SetBlocking(original)

	block := true
	config.UpdateServiceConfig(&aikido_types.CloudConfigData{
		Block: &block,
		Endpoints: []aikido_types.Endpoint{
			{
				Method:             "POST",
				Route:              "/api/danger",
				ForceProtectionOff: true,
			},
			{
				Method:             "*",
				Route:              "/api/wildcard",
				ForceProtectionOff: true,
			},
			{
				Method:             "GET",
				Route:              "/api/safe",
				ForceProtectionOff: false,
			},
		},
	}, nil)

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		body        any
		routeParams map[string]string
		expectError bool
		description string
	}{
		{
			name: "force protection off should not scan",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/api/danger?param1=attack&param2=safe", http.NoBody)
			},
			body:        nil,
			expectError: false,
			description: "route should not have protection",
		},
		{
			name: "wildcards should be respected",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/wildcard", http.NoBody)
				req.Header.Set("X-Custom-Header", "attack")
				return req
			},
			body:        nil,
			expectError: false,
			description: "route should match with wildcard method",
		},
		{
			name: "force protection off should still scan",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/safe", http.NoBody)
				req.AddCookie(&http.Cookie{Name: "session", Value: "attack"})
				return req
			},
			body:        nil,
			expectError: true,
		},
		{
			name: "unmatched routes should scan",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/api/danger?param1=attack&param2=safe", http.NoBody)
			},
			body:        nil,
			expectError: true,
			description: "route should be scanned with force protection off false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source: "test",
				// Route:         tt.route,
				RemoteAddress: &ip,
				RouteParams:   tt.routeParams,
				Body:          tt.body,
			})

			err := ScanWithOptions(ctx, "testOperation", mockVulnerability, args, ScanOptions{})
			if tt.expectError {
				require.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), "SQL injection")
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestScan_ShouldProtect(t *testing.T) {
	ip := "127.0.0.1"
	args := mockScanArgs{Value: "test"}

	// Enable blocking for tests that expect errors
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer config.SetBlocking(original)

	tests := []struct {
		name        string
		zenDisabled bool
		zenLoaded   bool
		expectError bool
		description string
	}{
		{
			name:        "zen is disabled",
			zenDisabled: true,
			zenLoaded:   true,
			expectError: false,
			description: "scanning should be skipped when zen is disabled",
		},
		{
			name:        "zen is not loaded",
			zenDisabled: false,
			zenLoaded:   false,
			expectError: false,
			description: "scanning should be skipped when zen is not loaded",
		},
		{
			name:        "zen is enabled and loaded",
			zenDisabled: false,
			zenLoaded:   true,
			expectError: true,
			description: "scanning should run when zen is enabled and loaded",
		},
		{
			name:        "zen is disabled and not loaded",
			zenDisabled: true,
			zenLoaded:   false,
			expectError: false,
			description: "scanning should be skipped when zen is disabled and not loaded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalDisabled := config.IsZenDisabled()
			originalLoaded := config.IsZenLoaded()
			t.Cleanup(func() {
				config.SetZenDisabled(originalDisabled)
				config.SetZenLoaded(originalLoaded)
			})

			config.SetZenDisabled(tt.zenDisabled)
			config.SetZenLoaded(tt.zenLoaded)

			req := httptest.NewRequest("GET", "/test?param1=attack&param2=safe", http.NoBody)
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/test",
				RemoteAddress: &ip,
			})

			err := ScanWithOptions(ctx, "testOperation", mockVulnerability, args, ScanOptions{})
			if tt.expectError {
				require.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), "SQL injection")
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
