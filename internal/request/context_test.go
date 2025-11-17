package request

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
)

func TestContext_GetUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected string
	}{
		{
			name:     "nil headers",
			headers:  nil,
			expected: "unknown",
		},
		{
			name:     "empty headers",
			headers:  map[string][]string{},
			expected: "unknown",
		},
		{
			name:     "no user-agent header",
			headers:  map[string][]string{"content-type": {"application/json"}},
			expected: "unknown",
		},
		{
			name:     "empty user-agent header",
			headers:  map[string][]string{"user-agent": {}},
			expected: "unknown",
		},
		{
			name:     "single user-agent",
			headers:  map[string][]string{"user-agent": {"Mozilla/5.0"}},
			expected: "Mozilla/5.0",
		},
		{
			name:     "multiple user-agents",
			headers:  map[string][]string{"user-agent": {"Mozilla/5.0", "Chrome/91.0"}},
			expected: "Mozilla/5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{Headers: tt.headers}
			result := ctx.GetUserAgent()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContext_SetUser_GetUserID(t *testing.T) {
	ctx := &Context{}

	// Test initial state
	assert.Empty(t, ctx.GetUserID())

	// Test setting user
	user := aikido_types.User{ID: "user123", Name: "Test User"}
	ctx.SetUser(user)
	assert.Equal(t, "user123", ctx.GetUserID())
}

func TestContext_MarkMiddlewareExecuted(t *testing.T) {
	ctx := &Context{}

	// First call should return true
	assert.True(t, ctx.MarkMiddlewareExecuted())

	// Second call should return false
	assert.False(t, ctx.MarkMiddlewareExecuted())
}

func TestContext_HasMiddlewareExecuted(t *testing.T) {
	ctx := &Context{}

	// Initially should be false
	assert.False(t, ctx.HasMiddlewareExecuted())

	// After marking as executed, should be true
	ctx.MarkMiddlewareExecuted()
	assert.True(t, ctx.HasMiddlewareExecuted())
}

func TestContext_GetIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddress *string
		expected      string
	}{
		{
			name:          "nil remote address",
			remoteAddress: nil,
			expected:      "",
		},
		{
			name:          "valid IP",
			remoteAddress: stringPtr("192.168.1.1"),
			expected:      "192.168.1.1",
		},
		{
			name:          "localhost IP",
			remoteAddress: stringPtr("127.0.0.1"),
			expected:      "127.0.0.1",
		},
		{
			name:          "empty IP",
			remoteAddress: stringPtr(""),
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{RemoteAddress: tt.remoteAddress}
			result := ctx.GetIP()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

func TestContext_SetDeferredAttack_GetDeferredAttack(t *testing.T) {
	ctx := &Context{}

	// Test initial state
	assert.Nil(t, ctx.GetDeferredAttack())

	// Test setting deferred attack
	attack := &DeferredAttack{
		Operation: "path.Join",
		Kind:      "path_traversal",
		Payload:   "../../etc/passwd",
	}
	ctx.SetDeferredAttack(attack)

	result := ctx.GetDeferredAttack()
	assert.NotNil(t, result)
	assert.Equal(t, "path.Join", result.Operation)
	assert.Equal(t, "path_traversal", result.Kind)
	assert.Equal(t, "../../etc/passwd", result.Payload)

	// Test setting nil
	ctx.SetDeferredAttack(nil)
	assert.Nil(t, ctx.GetDeferredAttack())
}

func TestDeferredAttack_ShouldReport(t *testing.T) {
	attack := &DeferredAttack{
		Operation: "test",
		Kind:      "test_attack",
	}

	// First call should return true
	assert.True(t, attack.ShouldReport())

	// Subsequent calls should return false
	assert.False(t, attack.ShouldReport())
	assert.False(t, attack.ShouldReport())
}
