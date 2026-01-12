package attackwave

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestQueryContainsDangerousPayload(t *testing.T) {
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
			name: "nil query",
			ctx: &request.Context{
				Query: nil,
			},
			expected: false,
		},
		{
			name: "normal query",
			ctx: &request.Context{
				Query: map[string][]string{
					"search": {"hello world"},
					"page":   {"1"},
				},
			},
			expected: false,
		},
		{
			name: "SQL injection - SELECT COUNT",
			ctx: &request.Context{
				Query: map[string][]string{
					"id": {"1 OR 1=1; SELECT COUNT(*) FROM users"},
				},
			},
			expected: true,
		},
		{
			name: "SQL injection - UNION SELECT",
			ctx: &request.Context{
				Query: map[string][]string{
					"id": {"1 UNION ALL SELECT username,password FROM users"},
				},
			},
			expected: true,
		},
		{
			name: "SQL injection - SLEEP",
			ctx: &request.Context{
				Query: map[string][]string{
					"id": {"1; SLEEP(10)"},
				},
			},
			expected: true,
		},
		{
			name: "SQL injection - WAITFOR DELAY",
			ctx: &request.Context{
				Query: map[string][]string{
					"id": {"1; WAITFOR DELAY '00:00:10'"},
				},
			},
			expected: true,
		},
		{
			name: "SQL injection - INFORMATION_SCHEMA",
			ctx: &request.Context{
				Query: map[string][]string{
					"table": {"users' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES--"},
				},
			},
			expected: true,
		},
		{
			name: "SQL injection - classic 1'='1",
			ctx: &request.Context{
				Query: map[string][]string{
					"user": {"admin' OR '1'='1"},
				},
			},
			expected: true,
		},
		{
			name: "Path traversal - ../",
			ctx: &request.Context{
				Query: map[string][]string{
					"file": {"../../etc/passwd"},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL - PG_SLEEP",
			ctx: &request.Context{
				Query: map[string][]string{
					"id": {"1; SELECT PG_SLEEP(10)"},
				},
			},
			expected: true,
		},
		{
			name: "MySQL - MD5",
			ctx: &request.Context{
				Query: map[string][]string{
					"test": {"' OR MD5('test')='test"},
				},
			},
			expected: true,
		},
		{
			name: "case insensitive matching",
			ctx: &request.Context{
				Query: map[string][]string{
					"q": {"select count(*) from users"},
				},
			},
			expected: true,
		},
		{
			name: "very short string - should skip",
			ctx: &request.Context{
				Query: map[string][]string{
					"q": {"abc"},
				},
			},
			expected: false,
		},
		{
			name: "legitimate query with SQL keywords",
			ctx: &request.Context{
				Query: map[string][]string{
					"title": {"How to SELECT the best database"},
				},
			},
			expected: false,
		},
		{
			name: "multiple query parameters - one dangerous",
			ctx: &request.Context{
				Query: map[string][]string{
					"page":   {"1"},
					"filter": {"name"},
					"sort":   {"1' OR '1'='1"},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := queryContainsDangerousPayload(tt.ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsDangerousPattern(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		expected bool
	}{
		// Too short
		{
			name:     "very short string",
			str:      "abc",
			expected: false,
		},
		{
			name:     "exactly 4 chars",
			str:      "test",
			expected: false,
		},

		// SQL injection patterns
		{
			name:     "SELECT * FROM",
			str:      "SELECT * FROM users WHERE id=1",
			expected: true,
		},
		{
			name:     "UNION ALL SELECT",
			str:      "1 UNION ALL SELECT password FROM admin",
			expected: true,
		},
		{
			name:     "SLEEP function",
			str:      "1; SLEEP(5); --",
			expected: true,
		},

		// Normal strings
		{
			name:     "normal search query",
			str:      "search for products",
			expected: false,
		},
		{
			name:     "email address",
			str:      "user@example.com",
			expected: false,
		},

		// Path traversal
		{
			name:     "path traversal",
			str:      "../../../etc/passwd",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsDangerousPattern(tt.str)
			assert.Equal(t, tt.expected, result)
		})
	}
}
