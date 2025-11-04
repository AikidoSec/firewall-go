package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCommand_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"zen-go", "init"}
	err = initCommand()
	require.NoError(t, err)

	// Verify file was created
	filename := "orchestrion.tool.go"
	_, err = os.Stat(filename)
	require.NoError(t, err)

	// Verify file content
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Contains(t, string(content), "github.com/AikidoSec/firewall-go/instrumentation")
}

func TestInitCommand_DoesNotOverwriteExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Create existing file
	filename := "orchestrion.tool.go"
	err = os.WriteFile(filename, []byte("existing content"), 0644)
	require.NoError(t, err)

	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"zen-go", "init"}
	err = initCommand()
	require.NoError(t, err)

	// Verify file content was not overwritten
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Equal(t, "existing content", string(content))
}

func TestInitCommand_ForceOverwritesExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Create existing file
	filename := "orchestrion.tool.go"
	err = os.WriteFile(filename, []byte("existing content"), 0644)
	require.NoError(t, err)

	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"zen-go", "init", "--force"}
	err = initCommand()
	require.NoError(t, err)

	// Verify file content was overwritten
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Contains(t, string(content), "github.com/AikidoSec/firewall-go/instrumentation")
	assert.NotEqual(t, "existing content", string(content))
}

func TestInitCommand_ForceShortFlag(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Create existing file
	filename := "orchestrion.tool.go"
	err = os.WriteFile(filename, []byte("existing content"), 0644)
	require.NoError(t, err)

	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"zen-go", "init", "-f"}
	err = initCommand()
	require.NoError(t, err)

	// Verify file content was overwritten
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Contains(t, string(content), "github.com/AikidoSec/firewall-go/instrumentation")
}

func TestToolsFileTemplate_ContainsRequiredImports(t *testing.T) {
	assert.Contains(t, toolsFileTemplate, "github.com/AikidoSec/firewall-go/instrumentation")
	assert.Contains(t, toolsFileTemplate, "github.com/DataDog/orchestrion")
	assert.Contains(t, toolsFileTemplate, "package tools")
}
