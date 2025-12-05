package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockTool creates a mock tool script that can be used for testing
func createMockTool(t *testing.T, name string, behavior string) string {
	t.Helper()
	tmpDir := t.TempDir()

	var script string
	if runtime.GOOS == "windows" {
		// Windows batch script
		script = "@echo off\n"
		switch behavior {
		case "success":
			script += "echo compiled successfully\n"
			script += "exit /b 0\n"
		case "failure":
			script += "echo compilation failed\n"
			script += "exit /b 1\n"
		case "echo":
			script += "echo %*\n"
		}
	} else {
		// Unix shell script
		script = "#!/bin/sh\n"
		switch behavior {
		case "success":
			script += "echo 'compiled successfully'\n"
			script += "exit 0\n"
		case "failure":
			script += "echo 'compilation failed' >&2\n"
			script += "exit 1\n"
		case "echo":
			script += "echo \"$@\"\n"
			script += "exit 0\n"
		}
	}

	toolPath := filepath.Join(tmpDir, name)
	if runtime.GOOS == "windows" {
		toolPath += ".bat"
	}

	// #nosec G306 - mock tool needs to be executable
	err := os.WriteFile(toolPath, []byte(script), 0o755)
	require.NoError(t, err)

	return toolPath
}

func TestExtractFlag(t *testing.T) {
	testCases := []struct {
		name     string
		args     []string
		index    int
		flag     string
		expected string
		found    bool
	}{
		{
			name:     "flag with space separator",
			args:     []string{"-p", "main"},
			index:    0,
			flag:     "-p",
			expected: "main",
			found:    true,
		},
		{
			name:     "flag with equals separator",
			args:     []string{"-p=main"},
			index:    0,
			flag:     "-p",
			expected: "main",
			found:    true,
		},
		{
			name:     "flag not found",
			args:     []string{"-o", "output.o"},
			index:    0,
			flag:     "-p",
			expected: "",
			found:    false,
		},
		{
			name:     "flag at end without value",
			args:     []string{"-p"},
			index:    0,
			flag:     "-p",
			expected: "",
			found:    false,
		},
		{
			name:     "equals separator with multiple args",
			args:     []string{"-importcfg=/tmp/cfg", "-o", "out.o"},
			index:    0,
			flag:     "-importcfg",
			expected: "/tmp/cfg",
			found:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, found := extractFlag(tc.args, tc.index, tc.flag)
			assert.Equal(t, tc.found, found)
			if found {
				assert.Equal(t, tc.expected, val)
			}
		})
	}
}

func TestPassthrough(t *testing.T) {
	mockTool := createMockTool(t, "tool", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	toolArgs := []string{"arg1", "arg2", "arg3"}
	err = passthrough(mockTool, toolArgs)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "arg1")
	assert.Contains(t, output, "arg2")
	assert.Contains(t, output, "arg3")
}

func TestPassthrough_Error(t *testing.T) {
	mockTool := createMockTool(t, "tool", "failure")

	// Capture stderr
	oldStderr := os.Stderr
	_, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	toolArgs := []string{}
	err = passthrough(mockTool, toolArgs)

	w.Close()
	os.Stderr = oldStderr

	require.Error(t, err)

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestToolexecCLI_UnknownToolPassthrough(t *testing.T) {
	// Test that unknown tools are passed through correctly
	mockTool := createMockTool(t, "link", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	args := []string{"zen-go", "toolexec", mockTool, "arg1", "arg2"}
	cmd := newCommand()
	cmd.Writer = os.Stdout
	cmd.ErrWriter = os.Stderr

	err = cmd.Run(context.Background(), args)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "arg1")
	assert.Contains(t, output, "arg2")
}

func TestPassthrough_PreservesExitCode(t *testing.T) {
	testCases := []struct {
		name         string
		behavior     string
		expectedCode int
	}{
		{
			name:         "success exit code 0",
			behavior:     "success",
			expectedCode: 0,
		},
		{
			name:         "failure exit code 1",
			behavior:     "failure",
			expectedCode: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTool := createMockTool(t, "tool", tc.behavior)

			// Capture stderr for error output
			oldStderr := os.Stderr
			_, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stderr = w

			toolArgs := []string{}
			err = passthrough(mockTool, toolArgs)

			w.Close()
			os.Stderr = oldStderr

			if tc.expectedCode == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
				assert.Equal(t, tc.expectedCode, exitErr.ExitCode())
			}
		})
	}
}

func TestPassthrough_WithComplexArgs(t *testing.T) {
	mockTool := createMockTool(t, "tool", "echo")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	// Test with complex arguments that might appear in real compile commands
	toolArgs := []string{
		"-p", "github.com/example/pkg",
		"-importcfg", "/tmp/importcfg",
		"-o", "/tmp/output.o",
		"-trimpath", "/tmp",
		"input.go",
	}
	err = passthrough(mockTool, toolArgs)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	output := buf.String()
	// Verify all arguments are passed through
	assert.Contains(t, output, "-p")
	assert.Contains(t, output, "github.com/example/pkg")
	assert.Contains(t, output, "-importcfg")
	assert.Contains(t, output, "/tmp/importcfg")
	assert.Contains(t, output, "-o")
	assert.Contains(t, output, "/tmp/output.o")
	assert.Contains(t, output, "-trimpath")
	assert.Contains(t, output, "input.go")
}
