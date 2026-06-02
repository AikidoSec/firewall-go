package attackwave

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSuspiciousPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		statusCode int
		expected   bool
	}{
		// Normal paths
		{
			name:       "normal API path",
			path:       "/api/users",
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "normal file path",
			path:       "/images/logo.png",
			statusCode: 200,
			expected:   false,
		},

		// Suspicious filenames
		{
			name:       ".env file",
			path:       "/.env",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".env in subdirectory",
			path:       "/app/.env",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".gitignore",
			path:       "/.gitignore",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "wp-config.php",
			path:       "/wp-config.php",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "config.json",
			path:       "/config.json",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "docker-compose.yml",
			path:       "/docker-compose.yml",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".htaccess",
			path:       "/.htaccess",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "passwd",
			path:       "/etc/passwd",
			statusCode: 404,
			expected:   true,
		},

		// Suspicious extensions
		{
			name:       ".bak extension",
			path:       "/backup.bak",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".sql extension",
			path:       "/dump.sql",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".db extension",
			path:       "/data.db",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".old extension",
			path:       "/config.old",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".sqlite extension",
			path:       "/database.sqlite",
			statusCode: 404,
			expected:   true,
		},

		// Suspicious directories
		{
			name:       ".git directory",
			path:       "/.git/config",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".ssh directory",
			path:       "/.ssh/id_rsa",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".docker directory",
			path:       "/.docker/config.json",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".aws directory",
			path:       "/.aws/credentials",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       ".kube directory",
			path:       "/.kube/config",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "tmp directory",
			path:       "/tmp/shell.php",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "apache directory",
			path:       "/apache/httpd.conf",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "system32 directory",
			path:       "C:/System32",
			statusCode: 404,
			expected:   true,
		},

		// Case insensitivity
		{
			name:       "uppercase .ENV",
			path:       "/.ENV",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "mixed case .Git",
			path:       "/.Git/config",
			statusCode: 404,
			expected:   true,
		},

		// Path traversal patterns
		{
			name:       "parent directory access",
			path:       "/../../etc/passwd",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "current directory",
			path:       "/./etc/passwd",
			statusCode: 404,
			expected:   true,
		},

		// Foreign extensions — only suspicious on 404
		{
			name:       "php extension with 404",
			path:       "/admin.php",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "php extension with 200 (may be proxied)",
			path:       "/admin.php",
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "jsp extension with 404",
			path:       "/app.jsp",
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "jsp extension with 200 (may be proxied)",
			path:       "/app.jsp",
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSuspiciousPath(tt.path, tt.statusCode)
			assert.Equal(t, tt.expected, result, "Path %s (status %d) should be %v", tt.path, tt.statusCode, tt.expected)
		})
	}
}
