package attackwave

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSuspiciousPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Normal paths
		{
			name:     "normal API path",
			path:     "/api/users",
			expected: false,
		},
		{
			name:     "normal file path",
			path:     "/images/logo.png",
			expected: false,
		},

		// Suspicious filenames
		{
			name:     ".env file",
			path:     "/.env",
			expected: true,
		},
		{
			name:     ".env in subdirectory",
			path:     "/app/.env",
			expected: true,
		},
		{
			name:     ".gitignore",
			path:     "/.gitignore",
			expected: true,
		},
		{
			name:     "wp-config.php",
			path:     "/wp-config.php",
			expected: true,
		},
		{
			name:     "config.json",
			path:     "/config.json",
			expected: true,
		},
		{
			name:     "docker-compose.yml",
			path:     "/docker-compose.yml",
			expected: true,
		},
		{
			name:     ".htaccess",
			path:     "/.htaccess",
			expected: true,
		},
		{
			name:     "passwd",
			path:     "/etc/passwd",
			expected: true,
		},

		// Suspicious extensions
		{
			name:     ".bak extension",
			path:     "/backup.bak",
			expected: true,
		},
		{
			name:     ".sql extension",
			path:     "/dump.sql",
			expected: true,
		},
		{
			name:     ".db extension",
			path:     "/data.db",
			expected: true,
		},
		{
			name:     ".old extension",
			path:     "/config.old",
			expected: true,
		},
		{
			name:     ".sqlite extension",
			path:     "/database.sqlite",
			expected: true,
		},

		// Suspicious directories
		{
			name:     ".git directory",
			path:     "/.git/config",
			expected: true,
		},
		{
			name:     ".ssh directory",
			path:     "/.ssh/id_rsa",
			expected: true,
		},
		{
			name:     ".docker directory",
			path:     "/.docker/config.json",
			expected: true,
		},
		{
			name:     ".aws directory",
			path:     "/.aws/credentials",
			expected: true,
		},
		{
			name:     ".kube directory",
			path:     "/.kube/config",
			expected: true,
		},
		{
			name:     "tmp directory",
			path:     "/tmp/shell.php",
			expected: true,
		},
		{
			name:     "apache directory",
			path:     "/apache/httpd.conf",
			expected: true,
		},

		// Case insensitivity
		{
			name:     "uppercase .ENV",
			path:     "/.ENV",
			expected: true,
		},
		{
			name:     "mixed case .Git",
			path:     "/.Git/config",
			expected: true,
		},

		// Path traversal patterns
		{
			name:     "parent directory access",
			path:     "/../../etc/passwd",
			expected: true,
		},
		{
			name:     "current directory",
			path:     "/./etc/passwd",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSuspiciousPath(tt.path)
			assert.Equal(t, tt.expected, result, "Path %s should be %v", tt.path, tt.expected)
		})
	}
}
