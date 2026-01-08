package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCommand_DoesNotOverwriteExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldDir) }()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Create existing file
	filename := "orchestrion.tool.go"
	err = os.WriteFile(filename, []byte("existing content"), 0o600)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = initCommand(&buf, false)
	require.NoError(t, err)

	// Verify file content was not overwritten
	content, err := os.ReadFile(filename)
	require.NoError(t, err)
	assert.Equal(t, "existing content", string(content))

	// Verify output message
	output := buf.String()
	assert.Contains(t, output, "already exists")
}

func TestGenerateToolsFile_WithSourcesAndSinks(t *testing.T) {
	config := initConfig{
		sources: []string{"gin", "chi"},
		sinks:   []string{"pgx"},
	}
	content := generateToolsFile(config)

	// Verify basic structure
	assert.Contains(t, content, "//go:build tools")
	assert.Contains(t, content, "package tools")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation")
	assert.Contains(t, content, "github.com/DataDog/orchestrion")

	// Verify sources section
	assert.Contains(t, content, "// Sources")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi")

	// Verify sinks section
	assert.Contains(t, content, "// Sinks")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")

	// Verify other sources/sinks are not included
	assert.NotContains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo")
}

func TestGenerateToolsFile_WithNoSourcesOrSinks(t *testing.T) {
	config := initConfig{
		sources: []string{},
		sinks:   []string{},
	}
	content := generateToolsFile(config)

	// Verify basic structure is always present
	assert.Contains(t, content, "package tools")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation")
	assert.Contains(t, content, "github.com/DataDog/orchestrion")

	// Verify no sources/sinks sections
	assert.NotContains(t, content, "// Sources")
	assert.NotContains(t, content, "// Sinks")
}

func TestGenerateToolsFile_OnlySourcesSelected(t *testing.T) {
	config := initConfig{
		sources: []string{"gin"},
		sinks:   []string{},
	}
	content := generateToolsFile(config)

	assert.Contains(t, content, "// Sources")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.NotContains(t, content, "// Sinks")
}

func TestGenerateToolsFile_OnlySinksSelected(t *testing.T) {
	config := initConfig{
		sources: []string{},
		sinks:   []string{"pgx"},
	}
	content := generateToolsFile(config)

	assert.NotContains(t, content, "// Sources")
	assert.Contains(t, content, "// Sinks")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")
}
