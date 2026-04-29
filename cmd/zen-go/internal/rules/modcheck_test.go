package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeGoMod(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "go.mod")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestCheckModuleVersionSync_Aligned(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sinks/pgx.v5 v1.2.0
)
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestCheckModuleVersionSync_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v1.1.1
)
`)
	err := CheckModuleVersionSync(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version mismatch")
	assert.Contains(t, err.Error(), "v1.2.0")
	assert.Contains(t, err.Error(), "gin is at v1.1.1")
	assert.Contains(t, err.Error(), "go get")
	assert.Contains(t, err.Error(), "gin@v1.2.0")
}

func TestCheckModuleVersionSync_MultipleMismatches(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v1.1.1
	github.com/AikidoSec/firewall-go/instrumentation/sinks/pgx.v5 v1.0.0
)
`)
	err := CheckModuleVersionSync(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gin is at v1.1.1")
	assert.Contains(t, err.Error(), "pgx.v5 is at v1.0.0")
	assert.Contains(t, err.Error(), "gin@v1.2.0")
	assert.Contains(t, err.Error(), "pgx.v5@v1.2.0")
}

func TestCheckModuleVersionSync_NoFirewallModule(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
)
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestCheckModuleVersionSync_MainModuleOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
)
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestCheckModuleVersionSync_UnreadableFile(t *testing.T) {
	require.NoError(t, CheckModuleVersionSync("/nonexistent/go.mod"))
}

func TestCheckModuleVersionSync_ReplacedSubmodule(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v0.0.0-00010101000000-000000000000
)

replace github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin => ../../instrumentation/sources/gin-gonic/gin
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestCheckModuleVersionSync_ReplacedMainModule(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v1.1.1
)

replace github.com/AikidoSec/firewall-go => ../../
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestCheckModuleVersionSync_PseudoVersionSkipped(t *testing.T) {
	dir := t.TempDir()
	path := writeGoMod(t, dir, `module example.com/app

go 1.22

require (
	github.com/AikidoSec/firewall-go v1.2.2-0.20260428123005-0cdd21ca0d12
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v1.2.1-beta.1.0.20260428123005-0cdd21ca0d12
)
`)
	require.NoError(t, CheckModuleVersionSync(path))
}

func TestFindGoMod_Found(t *testing.T) {
	root := t.TempDir()
	gomodPath := filepath.Join(root, "go.mod")
	require.NoError(t, os.WriteFile(gomodPath, []byte("module example.com/app\n"), 0o644))

	subdir := filepath.Join(root, "pkg", "handlers")
	require.NoError(t, os.MkdirAll(subdir, 0o755))

	assert.Equal(t, gomodPath, FindGoMod(subdir))
	assert.Equal(t, gomodPath, FindGoMod(root))
}

func TestFindGoMod_NotFound(t *testing.T) {
	dir := t.TempDir()
	assert.Equal(t, "", FindGoMod(dir))
}
