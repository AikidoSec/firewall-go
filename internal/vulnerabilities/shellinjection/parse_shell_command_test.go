package shellinjection_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/shellinjection"

	"github.com/stretchr/testify/assert"
)

func TestIsShellCommand(t *testing.T) {
	tests := []struct {
		name     string
		program  string
		expected bool
	}{
		// Unix shells
		{
			name:     "sh",
			program:  "sh",
			expected: true,
		},
		{
			name:     "bash",
			program:  "bash",
			expected: true,
		},
		{
			name:     "zsh",
			program:  "zsh",
			expected: true,
		},
		{
			name:     "dash",
			program:  "dash",
			expected: true,
		},
		{
			name:     "ksh",
			program:  "ksh",
			expected: true,
		},
		{
			name:     "fish",
			program:  "fish",
			expected: true,
		},
		{
			name:     "tcsh",
			program:  "tcsh",
			expected: true,
		},
		{
			name:     "csh",
			program:  "csh",
			expected: true,
		},
		// Unix shells with full paths
		{
			name:     "sh with full path",
			program:  "/bin/sh",
			expected: true,
		},
		{
			name:     "bash with full path",
			program:  "/usr/bin/bash",
			expected: true,
		},
		{
			name:     "zsh with full path",
			program:  "/usr/local/bin/zsh",
			expected: true,
		},
		// Case insensitivity
		{
			name:     "SH uppercase",
			program:  "SH",
			expected: true,
		},
		{
			name:     "BaSh mixed case",
			program:  "BaSh",
			expected: true,
		},
		// Non-shell programs
		{
			name:     "ls",
			program:  "ls",
			expected: false,
		},
		{
			name:     "cat",
			program:  "cat",
			expected: false,
		},
		{
			name:     "ping",
			program:  "ping",
			expected: false,
		},
		{
			name:     "python",
			program:  "python",
			expected: false,
		},
		{
			name:     "node",
			program:  "node",
			expected: false,
		},
		// Non-shell with full path
		{
			name:     "grep with full path",
			program:  "/usr/bin/grep",
			expected: false,
		},
		// Edge cases
		{
			name:     "empty string",
			program:  "",
			expected: false,
		},
		{
			name:     "shell-like name",
			program:  "shell",
			expected: false,
		},
		{
			name:     "bash suffix",
			program:  "mybash",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellinjection.IsShellCommand(tt.program)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractShellCommandString(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		// Unix -c flag
		{
			name:     "sh -c with single command",
			args:     []string{"sh", "-c", "ls ."},
			expected: []string{"ls ."},
		},
		{
			name:     "bash -c with command chain",
			args:     []string{"bash", "-c", "cat /etc/passwd"},
			expected: []string{"cat /etc/passwd"},
		},
		{
			name:     "sh -c with multiple arguments",
			args:     []string{"sh", "-c", "echo", "hello"},
			expected: []string{"echo", "hello"},
		},
		// No command flag
		{
			name:     "no -c flag",
			args:     []string{"sh", "script.sh"},
			expected: nil,
		},
		{
			name:     "direct command without shell",
			args:     []string{"ls", "-la"},
			expected: nil,
		},
		// Edge cases
		{
			name:     "empty args",
			args:     []string{},
			expected: nil,
		},
		{
			name:     "only shell name",
			args:     []string{"sh"},
			expected: nil,
		},
		{
			name:     "flag at the end with no command",
			args:     []string{"sh", "-c"},
			expected: nil,
		},
		{
			name:     "flag not in position 1",
			args:     []string{"sh", "--verbose", "-c", "ls ."},
			expected: []string{"ls ."},
		},
		{
			name:     "multiple flags, first one wins",
			args:     []string{"sh", "-c", "echo test", "-c", "other"},
			expected: []string{"echo test", "-c", "other"},
		},
		// Complex commands
		{
			name:     "command with semicolon injection",
			args:     []string{"sh", "-c", "ping 8.8.8.8;cat /etc/passwd"},
			expected: []string{"ping 8.8.8.8;cat /etc/passwd"},
		},
		{
			name:     "command with pipe",
			args:     []string{"bash", "-c", "cat file.txt | grep password"},
			expected: []string{"cat file.txt | grep password"},
		},
		{
			name:     "command with AND operator",
			args:     []string{"sh", "-c", "cd /tmp && rm -rf *"},
			expected: []string{"cd /tmp && rm -rf *"},
		},
		{
			name:     "command substitution",
			args:     []string{"bash", "-c", "cat $(whoami).txt"},
			expected: []string{"cat $(whoami).txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellinjection.ExtractShellCommandString(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}
