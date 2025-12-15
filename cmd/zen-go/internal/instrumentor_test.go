package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstrumentFile_GinDefault(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "zengin")
	assert.Equal(t, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin", result.Imports["zengin"])

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "GetMiddleware()")
	assert.Contains(t, resultStr, "e.Use(zengin.")
}

func TestInstrumentFile_GinNew(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "zengin")

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "GetMiddleware()")
}

func TestInstrumentFile_NoGin(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.False(t, result.Modified)
	assert.Empty(t, result.Imports)
}

func TestInstrumentFile_GinWithAlias(t *testing.T) {
	src := `package main

import g "github.com/gin-gonic/gin"

func main() {
	r := g.Default()
	r.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "zengin")

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "GetMiddleware()")
}

func TestInstrumentFile_MultipleGinCalls(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	r1 := gin.Default()
	r2 := gin.New()
	r1.Run()
	r2.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)

	resultStr := string(result.Code)
	// Should have two middleware insertions
	assert.Equal(t, 2, strings.Count(resultStr, "GetMiddleware()"))
}

func TestInstrumentFile_GinInIfStatement(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	if true {
		r := gin.Default()
		r.Run()
	}
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, string(result.Code), "GetMiddleware()")
}

func TestInstrumentFile_GinInFunction(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func createRouter() *gin.Engine {
	return gin.Default()
}

func main() {
	r := createRouter()
	r.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, string(result.Code), "GetMiddleware()")
}

func TestInstrumentFile_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "nonexistent.go")

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	assert.Error(t, err)
	assert.False(t, result.Modified)
	assert.Nil(t, result.Imports)
}

func TestInstrumentFile_InvalidSyntax(t *testing.T) {
	src := `package main

func main() {
	this is not valid go
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	result, err := inst.InstrumentFile(tmpFile, "main")

	assert.Error(t, err)
	assert.False(t, result.Modified)
	assert.Nil(t, result.Imports)
}

func TestInstrumentFile_InvalidTemplateSyntax(t *testing.T) {
	src := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.Run()
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentor()
	inst.WrapRules = []WrapRule{
		{
			ID:        "gin.Default",
			MatchCall: "github.com/gin-gonic/gin.Default",
			Imports: map[string]string{
				"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
			},
			WrapTmpl: `{.}}`,
		},
	}
	result, err := inst.InstrumentFile(tmpFile, "main")

	assert.Error(t, err)
	assert.False(t, result.Modified)
	assert.Nil(t, result.Imports)
}
