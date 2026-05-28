package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleGoMod = `module example.com/app

go 1.25

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/jackc/pgx/v5 v5.5.0
)

require (
	github.com/some/indirect v1.0.0 // indirect
)
`

func writeGoMod(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestParseGoModRequires_ReturnsAllRequires(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, sampleGoMod)

	requires, err := parseGoModRequires(path)
	require.NoError(t, err)

	assert.Contains(t, requires, "github.com/gin-gonic/gin")
	assert.Contains(t, requires, "github.com/jackc/pgx/v5")
	assert.Contains(t, requires, "github.com/some/indirect")
}

func TestParseGoModRequires_MissingFile(t *testing.T) {
	_, err := parseGoModRequires(filepath.Join(t.TempDir(), "missing.mod"))
	assert.Error(t, err)
}

func TestParseGoModRequires_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, "this is not a valid go.mod\n")

	_, err := parseGoModRequires(path)
	assert.Error(t, err)
}

func TestDetectInstalledOptions_MatchesByModulePath(t *testing.T) {
	requires := map[string]struct{}{
		"github.com/gin-gonic/gin": {},
		"github.com/jackc/pgx/v5":  {},
	}

	gotSources := detectInstalledOptions(sourceOptions, requires)
	assert.ElementsMatch(t, []string{"gin"}, gotSources)

	gotSinks := detectInstalledOptions(sinkOptions, requires)
	assert.ElementsMatch(t, []string{"pgx"}, gotSinks)
}

func TestDetectInstalledOptions_SkipsLocked(t *testing.T) {
	// net/http is locked in sourceOptions; it should never appear in detection.
	requires := map[string]struct{}{
		"net/http": {},
	}
	got := detectInstalledOptions(sourceOptions, requires)
	assert.Empty(t, got)
}

func TestDetectInstalledOptions_NoMatches(t *testing.T) {
	requires := map[string]struct{}{
		"github.com/unrelated/lib": {},
	}
	assert.Empty(t, detectInstalledOptions(sourceOptions, requires))
	assert.Empty(t, detectInstalledOptions(sinkOptions, requires))
}

func TestDetectInstalledOptions_NilRequires(t *testing.T) {
	assert.Empty(t, detectInstalledOptions(sourceOptions, nil))
}
