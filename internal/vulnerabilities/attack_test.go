package vulnerabilities

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDisplayNameForAttackKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     AttackKind
		expected string
	}{
		{"SQLInjection", KindSQLInjection, "an SQL injection"},
		{"PathTraversal", KindPathTraversal, "a path traversal attack"},
		{"ShellInjection", KindShellInjection, "a shell injection"},
		{"SSRF", KindSSRF, "a server-side request forgery"},
		{"Unknown", AttackKind("unknown"), "unknown attack type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDisplayNameForAttackKind(tt.kind)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterceptorResultToString(t *testing.T) {
	tests := []struct {
		name     string
		result   InterceptorResult
		expected string
	}{
		{
			name: "valid JSON",
			result: InterceptorResult{
				Kind:          KindSQLInjection,
				Operation:     "exec",
				Source:        "body",
				PathToPayload: ".query.id",
				Payload:       "1 OR 1=1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result.ToString()

			// Verify it's valid JSON
			var decoded InterceptorResult
			err := json.Unmarshal([]byte(result), &decoded)
			require.NoError(t, err)

			// Verify the decoded values match
			assert.Equal(t, tt.result.Kind, decoded.Kind)
			assert.Equal(t, tt.result.Operation, decoded.Operation)
		})
	}
}

func TestGetHeaders(t *testing.T) {
	headers := map[string][]string{
		"content-type": {"application/json"},
		"user-agent":   {"test-agent"},
	}

	reqCtx := &request.Context{
		Headers: headers,
	}

	result := getHeaders(reqCtx)

	// Verify it's a clone (modifications to result shouldn't affect original)
	result["x-test"] = []string{"test"}
	_, ok := headers["x-test"]
	assert.False(t, ok, "getHeaders() should return a cloned map")

	// Verify values match
	assert.Equal(t, []string{"application/json"}, result["content-type"])
	assert.Equal(t, []string{"test-agent"}, result["user-agent"])
}

func TestBuildAttackDetectedError(t *testing.T) {
	result := InterceptorResult{
		Kind:          KindPathTraversal,
		Operation:     "readFile",
		Source:        "query",
		PathToPayload: "../etc/passwd",
		Payload:       "../../etc/passwd",
	}

	err := buildAttackDetectedError(result)
	require.Error(t, err)

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "a path traversal attack")
	assert.Contains(t, errorMsg, "readFile")
	assert.Contains(t, errorMsg, "query")
}

func TestGetAttackDetected(t *testing.T) {
	ip := "127.0.0.1"
	req := httptest.NewRequest("POST", "/api/users", nil)
	req.Header.Set("Content-Type", "application/json")

	ctx := request.SetContext(context.Background(), req, "/api/users", "test", &ip, map[string]interface{}{"name": "test"})

	result := InterceptorResult{
		Kind:          KindSQLInjection,
		Operation:     "query",
		Source:        "body",
		PathToPayload: ".name",
		Payload:       "1 OR 1=1",
		Metadata:      map[string]string{"key": "value"},
	}

	atk := getAttackDetected(ctx, result)
	require.NotNil(t, atk)

	assert.Equal(t, ip, atk.Request.IPAddress)
	assert.Equal(t, "POST", atk.Request.Method)
	assert.Equal(t, string(KindSQLInjection), atk.Attack.Kind)
	assert.Equal(t, "query", atk.Attack.Operation)

	// Verify metadata is cloned
	atk.Attack.Metadata["key"] = "modified"
	assert.Equal(t, "value", result.Metadata["key"], "Metadata should be cloned, not referenced")
}

func TestGetAttackDetectedWithNilContext(t *testing.T) {
	result := InterceptorResult{
		Kind:      KindSQLInjection,
		Operation: "query",
	}

	atk := getAttackDetected(context.TODO(), result)
	assert.Nil(t, atk)

	atk = getAttackDetected(context.Background(), result)
	assert.Nil(t, atk)
}

func TestOnInterceptorResultWithNilResult(t *testing.T) {
	err := onInterceptorResult(context.Background(), nil)
	assert.NoError(t, err)
}
