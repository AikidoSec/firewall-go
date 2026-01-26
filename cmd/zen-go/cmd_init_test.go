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
	filename := "zen.tool.go"
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
	assert.Contains(t, content, "package main")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation")

	// Verify sources section
	assert.Contains(t, content, "// Aikido Zen: Sources")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi")

	// Verify sinks section
	assert.Contains(t, content, "// Aikido Zen: Sinks")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")

	// Verify other sources/sinks are not included
	assert.NotContains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v4")
}

func TestGenerateToolsFile_WithNoSourcesOrSinks(t *testing.T) {
	config := initConfig{
		sources: []string{},
		sinks:   []string{},
	}
	content := generateToolsFile(config)

	// Verify basic structure is always present
	assert.Contains(t, content, "package main")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation")

	// Verify no sources/sinks sections
	assert.NotContains(t, content, "// Aikido Zen: Sources")
	assert.NotContains(t, content, "// Aikido Zen: Sinks")
}

func TestGenerateToolsFile_OnlySourcesSelected(t *testing.T) {
	config := initConfig{
		sources: []string{"gin"},
		sinks:   []string{},
	}
	content := generateToolsFile(config)

	assert.Contains(t, content, "// Aikido Zen: Sources")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.NotContains(t, content, "// Aikido Zen: Sinks")
}

func TestGenerateToolsFile_OnlySinksSelected(t *testing.T) {
	config := initConfig{
		sources: []string{},
		sinks:   []string{"pgx"},
	}
	content := generateToolsFile(config)

	assert.NotContains(t, content, "// Aikido Zen: Sources")
	assert.Contains(t, content, "// Aikido Zen: Sinks")
	assert.Contains(t, content, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")
}
