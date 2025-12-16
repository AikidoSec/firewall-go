package attackwave

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestIsWebScanner(t *testing.T) {
	tests := []struct {
		name     string
		ctx      *request.Context
		expected bool
	}{
		{
			name:     "nil context",
			ctx:      nil,
			expected: false,
		},
		{
			name: "normal request",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/api/users",
			},
			expected: false,
		},
		{
			name: "suspicious method",
			ctx: &request.Context{
				Method: "BADMETHOD",
				Path:   "/api/users",
			},
			expected: true,
		},
		{
			name: "suspicious path - .env",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/.env",
			},
			expected: true,
		},
		{
			name: "suspicious path - .git",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/.git/config",
			},
			expected: true,
		},
		{
			name: "suspicious path - wp-config.php",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/wp-config.php",
			},
			expected: true,
		},
		{
			name: "suspicious query - SQL injection",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/api/search",
				Query: map[string][]string{
					"q": {"SELECT * FROM users"},
				},
			},
			expected: true,
		},
		{
			name: "suspicious query - path traversal",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/api/file",
				Query: map[string][]string{
					"path": {"../../etc/passwd"},
				},
			},
			expected: true,
		},
		{
			name: "normal query parameters",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/api/search",
				Query: map[string][]string{
					"q":    {"hello world"},
					"page": {"1"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWebScanner(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}
