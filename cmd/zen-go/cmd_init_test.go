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
	err = initCommand(&buf, false, "", false, "", false)
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

func TestParseAndValidateList_ValidSources(t *testing.T) {
	result, err := parseAndValidateList("gin,chi", availableSources, "source")
	require.NoError(t, err)
	assert.Equal(t, []string{"gin", "chi"}, result)
}

func TestParseAndValidateList_ValidSourcesWithWhitespace(t *testing.T) {
	result, err := parseAndValidateList("gin, chi , echo/v4", availableSources, "source")
	require.NoError(t, err)
	assert.Equal(t, []string{"gin", "chi", "echo/v4"}, result)
}

func TestParseAndValidateList_InvalidSource(t *testing.T) {
	result, err := parseAndValidateList("gin,invalid", availableSources, "source")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid source(s): invalid")
	assert.Contains(t, err.Error(), "Available sources:")
}

func TestParseAndValidateList_EmptyString(t *testing.T) {
	result, err := parseAndValidateList("", availableSources, "source")
	require.NoError(t, err)
	assert.Equal(t, []string{}, result)
}

func TestParseAndValidateList_ValidSinks(t *testing.T) {
	result, err := parseAndValidateList("pgx", availableSinks, "sink")
	require.NoError(t, err)
	assert.Equal(t, []string{"pgx"}, result)
}

func TestInitCommand_WithSourcesAndSinksFlags(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldDir) }()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = initCommand(&buf, false, "gin", true, "pgx", true)
	require.NoError(t, err)

	// Verify file was created
	filename := "zen.tool.go"
	content, err := os.ReadFile(filename)
	require.NoError(t, err)

	// Verify both sources and sinks are included
	contentStr := string(content)
	assert.Contains(t, contentStr, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.Contains(t, contentStr, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")

	// Verify output message
	output := buf.String()
	assert.Contains(t, output, "Created zen.tool.go")
	assert.Contains(t, output, "Sources: gin")
	assert.Contains(t, output, "Sinks: pgx")
}

func TestInitCommand_WithInvalidSource(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldDir) }()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = initCommand(&buf, false, "invalid", true, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source(s): invalid")
}

func TestInitCommand_WithEmptySourcesFlag(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldDir) }()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = initCommand(&buf, false, "", true, "pgx", true)
	require.NoError(t, err)

	// Verify file was created
	filename := "zen.tool.go"
	content, err := os.ReadFile(filename)
	require.NoError(t, err)

	// Verify no sources section
	contentStr := string(content)
	assert.NotContains(t, contentStr, "// Aikido Zen: Sources")

	// Verify sinks are included
	assert.Contains(t, contentStr, "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx")

	// Verify output message
	output := buf.String()
	assert.Contains(t, output, "No sources selected (empty argument provided)")
	assert.Contains(t, output, "Created zen.tool.go")
	assert.NotContains(t, output, "Sources:")
	assert.Contains(t, output, "Sinks: pgx")
}

func TestInitCommand_WithEmptySinksFlag(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(oldDir) }()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = initCommand(&buf, false, "gin", true, "", true)
	require.NoError(t, err)

	// Verify file was created
	filename := "zen.tool.go"
	content, err := os.ReadFile(filename)
	require.NoError(t, err)

	// Verify sources are included
	contentStr := string(content)
	assert.Contains(t, contentStr, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")

	// Verify no sinks section
	assert.NotContains(t, contentStr, "// Aikido Zen: Sinks")

	// Verify output message
	output := buf.String()
	assert.Contains(t, output, "No sinks selected (empty argument provided)")
	assert.Contains(t, output, "Created zen.tool.go")
	assert.Contains(t, output, "Sources: gin")
	assert.NotContains(t, output, "Sinks:")
}
