package vulnerabilities

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
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

func TestStoreDeferredAttack(t *testing.T) {
	t.Run("returns nil when result is nil", func(t *testing.T) {
		err := storeDeferredAttack(context.Background(), nil)
		assert.NoError(t, err)
	})

	t.Run("returns nil when context has no request context", func(t *testing.T) {
		result := &InterceptorResult{
			Kind:      KindPathTraversal,
			Operation: "filepath.Join",
		}
		err := storeDeferredAttack(context.Background(), result)
		assert.NoError(t, err)
	})

	t.Run("stores attack and error in context", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := request.SetContext(context.Background(), req, "/test", "test", &ip, nil)

		result := &InterceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
			Metadata:      map[string]string{"filename": "/tmp/../etc/passwd"},
		}

		original := config.IsBlockingEnabled()
		config.SetBlocking(true)
		defer config.SetBlocking(original)

		err := storeDeferredAttack(ctx, result)
		assert.NoError(t, err)

		reqCtx := request.GetContext(ctx)
		require.NotNil(t, reqCtx)
		deferredAttack := reqCtx.GetDeferredAttack()
		require.NotNil(t, deferredAttack)

		assert.Equal(t, "filepath.Join", deferredAttack.Operation)
		assert.Equal(t, string(KindPathTraversal), deferredAttack.Kind)
		assert.Equal(t, "../etc/passwd", deferredAttack.Payload)
		assert.NotNil(t, deferredAttack.Error)
		assert.Contains(t, deferredAttack.Error.Error(), "path traversal attack")
	})

	t.Run("does not store error when blocking is disabled", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := request.SetContext(context.Background(), req, "/test", "test", &ip, nil)

		result := &InterceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
		}

		original := config.IsBlockingEnabled()
		config.SetBlocking(false)
		defer config.SetBlocking(original)

		err := storeDeferredAttack(ctx, result)
		assert.NoError(t, err)

		reqCtx := request.GetContext(ctx)
		deferredAttack := reqCtx.GetDeferredAttack()
		require.NotNil(t, deferredAttack)
		assert.Nil(t, deferredAttack.Error, "Error should not be stored when attack is not intended to be blocked")
	})
}

func TestReportDeferredAttack(t *testing.T) {
	t.Run("does nothing when context has no request context", func(t *testing.T) {
		reportDeferredAttack(context.Background())
	})

	t.Run("does nothing when no deferred attack exists", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := request.SetContext(context.Background(), req, "/test", "test", &ip, nil)

		reportDeferredAttack(ctx)
	})

	t.Run("reports stored attack", func(t *testing.T) {
		ip := "127.0.0.1"
		req := httptest.NewRequest("GET", "/test", nil)
		ctx := request.SetContext(context.Background(), req, "/test", "test", &ip, nil)

		result := &InterceptorResult{
			Kind:          KindPathTraversal,
			Operation:     "filepath.Join",
			Source:        "query",
			PathToPayload: ".path",
			Payload:       "../etc/passwd",
		}

		err := storeDeferredAttack(ctx, result)
		require.NoError(t, err)

		reportDeferredAttack(ctx)
	})
}
