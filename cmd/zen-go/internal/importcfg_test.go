package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtendImportcfg_ExistingPackage(t *testing.T) {
	tmpDir := t.TempDir()
	importcfgPath := filepath.Join(tmpDir, "importcfg")

	content := `# import config
packagefile fmt=/usr/local/go/pkg/darwin_arm64/fmt.a
packagefile os=/usr/local/go/pkg/darwin_arm64/os.a
`
	require.NoError(t, os.WriteFile(importcfgPath, []byte(content), 0600))

	result, err := ExtendImportcfg(importcfgPath, map[string]string{
		"fmt": "fmt",
	}, tmpDir, os.Stderr, false)

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestExtendImportcfg_EmptyImports(t *testing.T) {
	tmpDir := t.TempDir()
	importcfgPath := filepath.Join(tmpDir, "importcfg")

	content := `# import config
packagefile fmt=/usr/local/go/pkg/darwin_arm64/fmt.a
`
	require.NoError(t, os.WriteFile(importcfgPath, []byte(content), 0600))

	result, err := ExtendImportcfg(importcfgPath, map[string]string{}, tmpDir, os.Stderr, false)

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestExtendImportcfg_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	importcfgPath := filepath.Join(tmpDir, "nonexistent")

	_, err := ExtendImportcfg(importcfgPath, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	}, tmpDir, os.Stderr, false)

	assert.Error(t, err)
}

func TestCreateTempFile_WithObjdir(t *testing.T) {
	tmpDir := t.TempDir()

	f, err := createTempFile(tmpDir)
	require.NoError(t, err)
	defer os.Remove(f.Name())
	defer f.Close()

	assert.Contains(t, f.Name(), filepath.Join(tmpDir, "zen-go"))
	assert.True(t, strings.HasSuffix(f.Name(), "importcfg.txt"))
}

func TestCreateTempFile_WithoutObjdir(t *testing.T) {
	f, err := createTempFile("")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	defer f.Close()

	assert.Contains(t, f.Name(), "importcfg_")
}

func TestFindModuleRoot(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origDir) }()

	tmpDir := t.TempDir()
	goModPath := filepath.Join(tmpDir, "go.mod")
	require.NoError(t, os.WriteFile(goModPath, []byte("module test\n"), 0600))

	subDir := filepath.Join(tmpDir, "subdir", "deeper")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.Chdir(subDir))

	root := findModuleRoot()

	expectedRoot, _ := filepath.EvalSymlinks(tmpDir)
	actualRoot, _ := filepath.EvalSymlinks(root)
	assert.Equal(t, expectedRoot, actualRoot)
}

func TestFindModuleRoot_NoGoMod(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origDir) }()

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))

	root := findModuleRoot()
	assert.Empty(t, root)
}

func TestExtendImportcfg_ParsesExistingEntries(t *testing.T) {
	tmpDir := t.TempDir()
	importcfgPath := filepath.Join(tmpDir, "importcfg")

	content := `# import config
packagefile fmt=/path/to/fmt.a
packagefile os=/path/to/os.a
packagefile github.com/gin-gonic/gin=/path/to/gin.a
`
	require.NoError(t, os.WriteFile(importcfgPath, []byte(content), 0600))

	result, err := ExtendImportcfg(importcfgPath, map[string]string{
		"gin": "github.com/gin-gonic/gin",
	}, tmpDir, os.Stderr, false)

	require.NoError(t, err)
	assert.Empty(t, result)
}
