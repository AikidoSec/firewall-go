package attackwave

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSuspiciousMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", false},
		{"POST", false},
		{"PUT", false},
		{"DELETE", false},
		{"PATCH", false},
		{"OPTIONS", false},
		{"HEAD", false},
		{"BADMETHOD", true},
		{"BADHTTPMETHOD", true},
		{"BADDATA", true},
		{"BADMTHD", true},
		{"BDMTHD", true},
		{"badmethod", true}, // Case insensitive
		{"BadMethod", true}, // Case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := isSuspiciousMethod(tt.method)
			assert.Equal(t, tt.expected, result, "Method %s should be %v", tt.method, tt.expected)
		})
	}
}
