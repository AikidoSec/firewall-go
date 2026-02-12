package paths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindModuleRoot_InModuleRoot(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n"), 0o644))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, os.Chdir(dir))

	assert.Equal(t, dir, FindModuleRoot())
}

func TestFindModuleRoot_InSubdirectory(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n"), 0o644))
	subDir := filepath.Join(dir, "pkg", "internal")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, os.Chdir(subDir))

	assert.Equal(t, dir, FindModuleRoot())
}

func TestFindModuleRoot_NoGoMod(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, os.Chdir(dir))

	assert.Equal(t, "", FindModuleRoot())
}

func TestFindModuleRoot_NestedGoMod(t *testing.T) {
	// When go.mod exists in both current dir and parent, the current dir wins
	parentDir := t.TempDir()
	parentDir, err := filepath.EvalSymlinks(parentDir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(parentDir, "go.mod"), []byte("module parent\n"), 0o644))

	childDir := filepath.Join(parentDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(childDir, "go.mod"), []byte("module child\n"), 0o644))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, os.Chdir(childDir))

	assert.Equal(t, childDir, FindModuleRoot())
}

func TestFindModuleRoot_DeeplyNestedSubdirectory(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n"), 0o644))
	deepDir := filepath.Join(dir, "a", "b", "c", "d")
	require.NoError(t, os.MkdirAll(deepDir, 0o755))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, os.Chdir(deepDir))

	assert.Equal(t, dir, FindModuleRoot())
}

func TestCollectInstrumentationDirs_InstrumentationIsFile(t *testing.T) {
	// "instrumentation" exists but is a file, not a directory
	rootDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "instrumentation"), []byte("not a dir"), 0o644))

	dirs := collectInstrumentationDirs(rootDir, nil)

	assert.Empty(t, dirs)
}

func TestCollectInstrumentationDirs_RootAndSeparateSubmodules(t *testing.T) {
	// Simulate module cache layout where submodules are in separate directories
	// (this is the case when packages are installed via go get)
	rootDir := t.TempDir()
	instDir := filepath.Join(rootDir, "instrumentation")
	require.NoError(t, os.MkdirAll(filepath.Join(instDir, "sinks", "os"), 0o755))

	ginDir := t.TempDir() // Separate dir for gin submodule
	pgxDir := t.TempDir() // Separate dir for pgx submodule

	dirs := collectInstrumentationDirs(rootDir, []string{ginDir, pgxDir})

	assert.Equal(t, []string{instDir, ginDir, pgxDir}, dirs)
}

func TestCollectInstrumentationDirs_ReplaceDirective(t *testing.T) {
	// Simulate local development with replace directives:
	// submodule dirs are subdirectories of the root instrumentation dir.
	// Both are included because LoadRulesFromDir handles dedup by skipping
	// subdirectories that have their own go.mod.
	rootDir := t.TempDir()
	instDir := filepath.Join(rootDir, "instrumentation")
	ginDir := filepath.Join(instDir, "sources", "gin-gonic", "gin")
	pgxDir := filepath.Join(instDir, "sinks", "jackc", "pgx.v5")

	require.NoError(t, os.MkdirAll(ginDir, 0o755))
	require.NoError(t, os.MkdirAll(pgxDir, 0o755))

	dirs := collectInstrumentationDirs(rootDir, []string{ginDir, pgxDir})

	// All dirs are returned; LoadRulesFromDir skips submodule subdirs during walk
	assert.Equal(t, []string{instDir, ginDir, pgxDir}, dirs)
}

func TestCollectInstrumentationDirs_NoRootModule(t *testing.T) {
	// Only submodules, no root module (e.g., user only imports a specific instrumentation package)
	ginDir := t.TempDir()

	dirs := collectInstrumentationDirs("", []string{ginDir})

	assert.Equal(t, []string{ginDir}, dirs)
}

func TestCollectInstrumentationDirs_NoSubmodules(t *testing.T) {
	// Only root module, no submodules
	rootDir := t.TempDir()
	instDir := filepath.Join(rootDir, "instrumentation")
	require.NoError(t, os.MkdirAll(instDir, 0o755))

	dirs := collectInstrumentationDirs(rootDir, nil)

	assert.Equal(t, []string{instDir}, dirs)
}

func TestCollectInstrumentationDirs_Empty(t *testing.T) {
	dirs := collectInstrumentationDirs("", nil)

	assert.Empty(t, dirs)
}

func TestCollectInstrumentationDirs_RootWithoutInstrumentationDir(t *testing.T) {
	// Root module exists but has no instrumentation/ subdirectory
	rootDir := t.TempDir()
	ginDir := t.TempDir()

	dirs := collectInstrumentationDirs(rootDir, []string{ginDir})

	// Only submodule dir should be returned since root has no instrumentation/
	assert.Equal(t, []string{ginDir}, dirs)
}

func TestCollectInstrumentationDirs_NonexistentRootModule(t *testing.T) {
	// Root module path doesn't exist on disk
	dirs := collectInstrumentationDirs("/nonexistent/path", nil)

	assert.Empty(t, dirs)
}
