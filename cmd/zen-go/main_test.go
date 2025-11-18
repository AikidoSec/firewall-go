package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintUsage(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	output := buf.String()

	assert.Contains(t, output, "zen-go - Aikido Zen CLI tool for Go")
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "Commands:")
	assert.Contains(t, output, "init")
	assert.Contains(t, output, "version")
	assert.Contains(t, output, "help")
	assert.Contains(t, output, "Examples:")
}

func TestVersion(t *testing.T) {
	assert.Equal(t, "0.0.0", version)
}

func TestRun(t *testing.T) {
	testCases := []struct {
		name           string
		args           []string
		wantError      bool
		errorContains  string
		stdoutContains []string
		stderrContains []string
		setupDir       func(*testing.T)
	}{
		{
			name:           "no args",
			args:           []string{"zen-go"},
			wantError:      true,
			errorContains:  "no command provided",
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "version command",
			args:           []string{"zen-go", "version"},
			wantError:      false,
			stdoutContains: []string{"zen-go version 0.0.0"},
		},
		{
			name:           "version short flag -v",
			args:           []string{"zen-go", "-v"},
			wantError:      false,
			stdoutContains: []string{"zen-go version 0.0.0"},
		},
		{
			name:           "version long flag --version",
			args:           []string{"zen-go", "--version"},
			wantError:      false,
			stdoutContains: []string{"zen-go version 0.0.0"},
		},
		{
			name:           "help command",
			args:           []string{"zen-go", "help"},
			wantError:      false,
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go", "Usage:"},
		},
		{
			name:           "help short flag -h",
			args:           []string{"zen-go", "-h"},
			wantError:      false,
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go", "Usage:"},
		},
		{
			name:           "help long flag --help",
			args:           []string{"zen-go", "--help"},
			wantError:      false,
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go", "Usage:"},
		},
		{
			name:           "unknown command",
			args:           []string{"zen-go", "unknown-command"},
			wantError:      true,
			errorContains:  "unknown command: unknown-command",
			stderrContains: []string{"Unknown command: unknown-command"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "init command",
			args:           []string{"zen-go", "init"},
			wantError:      false,
			stdoutContains: []string{"✓ Created orchestrion.tool.go"},
			setupDir: func(t *testing.T) {
				tmpDir := t.TempDir()
				oldDir, err := os.Getwd()
				require.NoError(t, err)
				t.Cleanup(func() { _ = os.Chdir(oldDir) })
				err = os.Chdir(tmpDir)
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupDir != nil {
				tc.setupDir(t)
			}

			var stdoutBuf, stderrBuf bytes.Buffer
			err := run(tc.args, &stdoutBuf, &stderrBuf)

			if tc.wantError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
			}

			for _, contains := range tc.stdoutContains {
				assert.Contains(t, stdoutBuf.String(), contains)
			}

			for _, contains := range tc.stderrContains {
				assert.Contains(t, stderrBuf.String(), contains)
			}
		})
	}
}
