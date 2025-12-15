package zen_test

import (
	"errors"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackKind_Constants(t *testing.T) {
	tests := []struct {
		name     string
		kind     zen.AttackKind
		expected string
	}{
		{"SQL injection", zen.KindSQLInjection, "sql_injection"},
		{"path traversal", zen.KindPathTraversal, "path_traversal"},
		{"shell injection", zen.KindShellInjection, "shell_injection"},
		{"SSRF", zen.KindSSRF, "ssrf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.kind))
		})
	}
}

func TestAttackBlockedError_Error(t *testing.T) {
	tests := []struct {
		name     string
		kind     zen.AttackKind
		expected string
	}{
		{
			name:     "SQL injection",
			kind:     zen.KindSQLInjection,
			expected: "zen blocked sql_injection attack",
		},
		{
			name:     "path traversal",
			kind:     zen.KindPathTraversal,
			expected: "zen blocked path_traversal attack",
		},
		{
			name:     "shell injection",
			kind:     zen.KindShellInjection,
			expected: "zen blocked shell_injection attack",
		},
		{
			name:     "SSRF",
			kind:     zen.KindSSRF,
			expected: "zen blocked ssrf attack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &zen.AttackBlockedError{Kind: tt.kind}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrAttackBlocked(t *testing.T) {
	tests := []struct {
		name         string
		kind         vulnerabilities.AttackKind
		expectedKind zen.AttackKind
		expectedMsg  string
	}{
		{
			name:         "SQL injection",
			kind:         vulnerabilities.KindSQLInjection,
			expectedKind: zen.KindSQLInjection,
			expectedMsg:  "zen blocked sql_injection attack",
		},
		{
			name:         "path traversal",
			kind:         vulnerabilities.KindPathTraversal,
			expectedKind: zen.KindPathTraversal,
			expectedMsg:  "zen blocked path_traversal attack",
		},
		{
			name:         "shell injection",
			kind:         vulnerabilities.KindShellInjection,
			expectedKind: zen.KindShellInjection,
			expectedMsg:  "zen blocked shell_injection attack",
		},
		{
			name:         "SSRF",
			kind:         vulnerabilities.KindSSRF,
			expectedKind: zen.KindSSRF,
			expectedMsg:  "zen blocked ssrf attack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := zen.ErrAttackBlocked(tt.kind)

			// Check error message
			assert.Equal(t, tt.expectedMsg, err.Error())

			// Check it's the right type using errors.As
			var attackErr *zen.AttackBlockedError
			require.True(t, errors.As(err, &attackErr), "errors.As should extract *AttackBlockedError")

			// Verify the kind was correctly set
			assert.Equal(t, tt.expectedKind, attackErr.Kind)
		})
	}
}

func TestAttackBlockedError_ErrorsAs(t *testing.T) {
	err := zen.ErrAttackBlocked(vulnerabilities.KindSQLInjection)

	var attackErr *zen.AttackBlockedError
	require.True(t, errors.As(err, &attackErr), "errors.As should work with *AttackBlockedError")
	assert.Equal(t, zen.KindSQLInjection, attackErr.Kind)
}

func TestAttackBlockedError_ErrorsIs(t *testing.T) {
	// Test that two errors with the same kind are not considered equal by errors.Is
	// (they shouldn't be, as they're pointer types)
	err1 := zen.ErrAttackBlocked(vulnerabilities.KindSQLInjection)
	err2 := zen.ErrAttackBlocked(vulnerabilities.KindSQLInjection)

	assert.False(t, errors.Is(err1, err2), "errors.Is should return false for different *AttackBlockedError instances")
}
