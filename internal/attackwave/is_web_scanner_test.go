package attackwave

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestIsWebScanner(t *testing.T) {
	tests := []struct {
		name       string
		ctx        *request.Context
		statusCode int
		expected   bool
	}{
		{
			name:       "nil context",
			ctx:        nil,
			statusCode: 200,
			expected:   false,
		},
		{
			name: "normal request",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/api/users",
			},
			statusCode: 200,
			expected:   false,
		},
		{
			name: "suspicious method",
			ctx: &request.Context{
				Method: "BADMETHOD",
				Path:   "/api/users",
			},
			statusCode: 200,
			expected:   true,
		},
		{
			name: "suspicious path - .env",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/.env",
			},
			statusCode: 404,
			expected:   true,
		},
		{
			name: "suspicious path - .git",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/.git/config",
			},
			statusCode: 404,
			expected:   true,
		},
		{
			name: "suspicious path - wp-config.php",
			ctx: &request.Context{
				Method: "GET",
				Path:   "/wp-config.php",
			},
			statusCode: 404,
			expected:   true,
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
			statusCode: 200,
			expected:   true,
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
			statusCode: 200,
			expected:   true,
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
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWebScanner(tt.ctx, tt.statusCode)
			assert.Equal(t, tt.expected, result)
		})
	}
}
