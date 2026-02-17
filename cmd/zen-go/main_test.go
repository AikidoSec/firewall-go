package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	assert.Equal(t, "0.2.0", version)
}

func TestCLI(t *testing.T) {
	testCases := []struct {
		name           string
		args           []string
		errorContains  string
		stdoutContains []string
		stderrContains []string
		setupDir       func(*testing.T)
	}{
		{
			name:           "version short flag -v",
			args:           []string{"zen-go", "-v"},
			stdoutContains: []string{"zen-go version 0.2.0"},
		},
		{
			name:           "version long flag --version",
			args:           []string{"zen-go", "--version"},
			stdoutContains: []string{"zen-go version 0.2.0"},
		},
		{
			name:           "help command",
			args:           []string{"zen-go", "help"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "help short flag -h",
			args:           []string{"zen-go", "-h"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
		{
			name:           "help long flag --help",
			args:           []string{"zen-go", "--help"},
			stdoutContains: []string{"zen-go - Aikido Zen CLI tool for Go"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupDir != nil {
				tc.setupDir(t)
			}

			var stdoutBuf, stderrBuf bytes.Buffer
			cmd := newCommand()
			cmd.Writer = &stdoutBuf
			cmd.ErrWriter = &stderrBuf

			err := cmd.Run(context.Background(), tc.args)
			require.NoError(t, err)

			for _, contains := range tc.stdoutContains {
				assert.Contains(t, stdoutBuf.String(), contains)
			}

			for _, contains := range tc.stderrContains {
				assert.Contains(t, stderrBuf.String(), contains)
			}
		})
	}
}

func TestToolexecZenGoLog(t *testing.T) {
	t.Run("writes tool stdout to log file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "zen-go.log")
		t.Setenv("ZENGO_LOG", logFile)

		mockTool := createMockTool(t, "sometool", "success")

		cmd := newCommand()
		cmd.Writer = os.Stdout
		cmd.ErrWriter = os.Stderr
		err := cmd.Run(context.Background(), []string{"zen-go", "toolexec", mockTool})
		require.NoError(t, err)

		content, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), "compiled successfully")
	})

	t.Run("appends to existing log file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "zen-go.log")
		require.NoError(t, os.WriteFile(logFile, []byte("previous log\n"), 0o600))
		t.Setenv("ZENGO_LOG", logFile)

		mockTool := createMockTool(t, "sometool", "success")

		cmd := newCommand()
		cmd.Writer = os.Stdout
		cmd.ErrWriter = os.Stderr
		err := cmd.Run(context.Background(), []string{"zen-go", "toolexec", mockTool})
		require.NoError(t, err)

		content, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), "previous log")
		assert.Contains(t, string(content), "compiled successfully")
	})

	t.Run("returns error for invalid log path", func(t *testing.T) {
		t.Setenv("ZENGO_LOG", "/nonexistent/dir/zen-go.log")

		mockTool := createMockTool(t, "sometool", "success")

		cmd := newCommand()
		cmd.Writer = os.Stdout
		cmd.ErrWriter = os.Stderr
		err := cmd.Run(context.Background(), []string{"zen-go", "toolexec", mockTool})
		require.Error(t, err)
	})

	t.Run("writes debug stderr to log file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "zen-go.log")
		t.Setenv("ZENGO_LOG", logFile)
		t.Setenv("ZENGO_DEBUG", "1")

		// Use a mock "compile" tool so toolexecCompileCommand runs and emits debug output to stderr
		mockTool := createVersionMockTool(t, "compile version go1.25.0")
		// Rename the mock to "compile" so the switch matches
		compilePath := filepath.Join(filepath.Dir(mockTool), "compile")
		require.NoError(t, os.Rename(mockTool, compilePath))

		cmd := newCommand()
		cmd.Writer = os.Stdout
		cmd.ErrWriter = os.Stderr
		err := cmd.Run(context.Background(), []string{"zen-go", "toolexec", compilePath, "-V=full"})
		require.NoError(t, err)

		content, err := os.ReadFile(logFile)
		require.NoError(t, err)
		assert.Contains(t, string(content), "zen-go:")
	})
}

func TestToolexecNoToolSpecified(t *testing.T) {
	cmd := newCommand()
	cmd.Writer = os.Stdout
	cmd.ErrWriter = os.Stderr
	err := cmd.Run(context.Background(), []string{"zen-go", "toolexec"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no tool specified")
}

func TestIsDebug(t *testing.T) {
	t.Run("returns true when ZENGO_DEBUG is set", func(t *testing.T) {
		t.Setenv("ZENGO_DEBUG", "1")
		assert.True(t, isDebug())
	})

	t.Run("returns false when ZENGO_DEBUG is not set", func(t *testing.T) {
		t.Setenv("ZENGO_DEBUG", "")
		assert.False(t, isDebug())
	})
}
