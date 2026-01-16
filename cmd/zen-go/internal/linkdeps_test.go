package internal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteLinkDeps_Success(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")

	deps := []string{
		"github.com/example/pkg1",
		"github.com/example/pkg2",
	}

	var stderr bytes.Buffer
	err := WriteLinkDeps(archivePath, deps, &stderr, false)
	require.NoError(t, err)

	depsFile := archivePath + ".zenlinkdeps"
	content, err := os.ReadFile(depsFile)
	require.NoError(t, err)

	assert.Equal(t, "github.com/example/pkg1\ngithub.com/example/pkg2", string(content))
}

func TestWriteLinkDeps_DebugOutput(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")

	deps := []string{"github.com/example/pkg"}

	var stderr bytes.Buffer
	err := WriteLinkDeps(archivePath, deps, &stderr, true)
	require.NoError(t, err)

	assert.Contains(t, stderr.String(), "zen-go: wrote link deps to")
	assert.Contains(t, stderr.String(), "github.com/example/pkg")
}

func TestReadLinkDeps_Success(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")
	depsFile := archivePath + ".zenlinkdeps"

	content := "github.com/example/pkg1\ngithub.com/example/pkg2\n"
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(depsFile, []byte(content), 0o644))

	deps, err := ReadLinkDeps(archivePath)
	require.NoError(t, err)

	assert.Equal(t, []string{"github.com/example/pkg1", "github.com/example/pkg2"}, deps)
}

func TestReadLinkDeps_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "nonexistent.a")

	deps, err := ReadLinkDeps(archivePath)
	require.NoError(t, err)
	assert.Nil(t, deps)
}

func TestReadLinkDeps_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")
	depsFile := archivePath + ".zenlinkdeps"

	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(depsFile, []byte(""), 0o644))

	deps, err := ReadLinkDeps(archivePath)
	require.NoError(t, err)
	assert.Nil(t, deps)
}

func TestReadLinkDeps_SkipsEmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")
	depsFile := archivePath + ".zenlinkdeps"

	content := "github.com/example/pkg1\n\n  \ngithub.com/example/pkg2\n"
	// #nosec G306 -- test file
	require.NoError(t, os.WriteFile(depsFile, []byte(content), 0o644))

	deps, err := ReadLinkDeps(archivePath)
	require.NoError(t, err)

	assert.Equal(t, []string{"github.com/example/pkg1", "github.com/example/pkg2"}, deps)
}

func TestWriteAndReadLinkDeps_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.a")

	original := []string{
		"github.com/AikidoSec/firewall-go/internal/agent",
		"github.com/AikidoSec/firewall-go/internal/request",
	}

	var stderr bytes.Buffer
	err := WriteLinkDeps(archivePath, original, &stderr, false)
	require.NoError(t, err)

	read, err := ReadLinkDeps(archivePath)
	require.NoError(t, err)

	assert.Equal(t, original, read)
}
