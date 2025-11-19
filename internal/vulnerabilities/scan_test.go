package vulnerabilities

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		expectError bool
		description string
	}{
		{
			name: "query parameters are scanned",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test?param1=attack&param2=safe", nil)
			},
			body:        nil,
			expectError: true,
			description: "query parameters should be scanned",
		},
		{
			name: "headers are scanned",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
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
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{Name: "session", Value: "attack"})
				return req
			},
			body:        nil,
			expectError: true,
			description: "cookies should be scanned",
		},
		{
			name: "body is scanned - string",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", nil)
			},
			body:        "attack",
			expectError: true,
			description: "body string should be scanned",
		},
		{
			name: "body is scanned - map",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", nil)
			},
			body:        map[string]any{"field": "attack"},
			expectError: true,
			description: "body map should be scanned",
		},
		{
			name: "body is scanned - nested map",
			setupReq: func() *http.Request {
				return httptest.NewRequest("POST", "/test", nil)
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
				return httptest.NewRequest("POST", "/test", nil)
			},
			body:        []any{"attack", "safe"},
			expectError: true,
			description: "body array should be scanned",
		},
		{
			name: "query with multiple values per key",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test?param=value1&param=value2&param=attack", nil)
			},
			body:        nil,
			expectError: true,
			description: "query parameters with multiple values should be scanned",
		},
		{
			name: "headers with multiple values",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
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
	req := httptest.NewRequest("GET", "/test?queryParam=queryValue", nil)
	req.Header.Set("X-Header", "headerValue")
	req.AddCookie(&http.Cookie{Name: "cookie1", Value: "cookieValue"})
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "test",
		Route:         "/test",
		RemoteAddress: &ip,
		Body:          map[string]any{"bodyField": "bodyValue"},
	})

	err := ScanWithOptions(ctx, "testOperation", trackingVuln, args, ScanOptions{})
	assert.NoError(t, err)

	// Verify all sources were scanned by checking that values from each source appear
	// Note: extractStringsFromUserInput extracts both keys and values from maps
	assert.True(t, scannedInputs["queryValue"], "query parameters should be scanned")
	assert.True(t, scannedInputs["headerValue"], "headers should be scanned")
	assert.True(t, scannedInputs["cookieValue"], "cookies should be scanned")
	assert.True(t, scannedInputs["bodyValue"], "body should be scanned")
}

func TestScanWithOptions_NilContext(t *testing.T) {
	args := mockScanArgs{Value: "test"}
	ctx := context.Background()
	err := ScanWithOptions(ctx, "testOperation", mockVulnerability, args, ScanOptions{})
	assert.NoError(t, err)
}
