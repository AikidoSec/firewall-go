package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createVersionMockTool creates a mock tool that outputs a specific version string.
func createVersionMockTool(t *testing.T, versionOutput string) string {
	t.Helper()
	tmpDir := t.TempDir()

	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\nexit 0\n", versionOutput)

	toolPath := filepath.Join(tmpDir, "mock-compiler")

	// #nosec G306 - mock tool needs to be executable
	require.NoError(t, os.WriteFile(toolPath, []byte(script), 0o755))
	return toolPath
}

func TestToolexecVersionQueryCommand_OutputFormat(t *testing.T) {
	const toolVersion = "compile version go1.25.0 X:buildcoverage"
	mockTool := createVersionMockTool(t, toolVersion)

	var stdout, stderr bytes.Buffer
	require.NoError(t, toolexecVersionQueryCommand(&stdout, &stderr, mockTool, []string{"-V=full"}))

	output := strings.TrimSpace(stdout.String())
	// Should be "<tool version>:zen-go@<hash>" with a trailing newline
	parts := strings.SplitN(output, ":zen-go@", 2)
	require.Len(t, parts, 2, "output should contain ':zen-go@' separator")
	assert.Equal(t, toolVersion, parts[0])
	assert.NotEmpty(t, parts[1], "hash should not be empty")
	assert.True(t, strings.HasSuffix(stdout.String(), "\n"), "output should end with a newline")
}

func TestToolexecVersionQueryCommand_ToolError(t *testing.T) {
	mockTool := createMockTool(t, "failing-compiler", "failure")

	var stdout, stderr bytes.Buffer
	err := toolexecVersionQueryCommand(&stdout, &stderr, mockTool, []string{"-V=full"})

	require.Error(t, err)
	assert.Empty(t, stdout.String())
}

func TestToolexecVersionQueryCommand_HashIsStable(t *testing.T) {
	mockTool := createVersionMockTool(t, "compile version go1.25.0")

	var stdout1, stdout2, stderr bytes.Buffer
	require.NoError(t, toolexecVersionQueryCommand(&stdout1, &stderr, mockTool, []string{"-V=full"}))
	stderr.Reset()
	require.NoError(t, toolexecVersionQueryCommand(&stdout2, &stderr, mockTool, []string{"-V=full"}))

	assert.Equal(t, stdout1.String(), stdout2.String(), "version output should be stable across calls")
}

func TestToolexecVersionQueryCommand_DebugLogsToStderr(t *testing.T) {
	t.Setenv("ZENGO_DEBUG", "1")

	mockTool := createVersionMockTool(t, "compile version go1.25.0")

	var stdout, stderr bytes.Buffer
	require.NoError(t, toolexecVersionQueryCommand(&stdout, &stderr, mockTool, []string{"-V=full"}))

	assert.Contains(t, stderr.String(), "zen-go: version query:")
}
