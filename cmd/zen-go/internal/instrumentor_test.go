package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testChiRules returns rules for testing chi instrumentation (with /v5 version in path)
func testChiRules() []WrapRule {
	return []WrapRule{
		{
			ID:        "chi.NewMux",
			MatchCall: "github.com/go-chi/chi/v5.NewMux",
			Imports: map[string]string{
				"zenchi": "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi",
			},
			WrapTmpl: `func() *chi.Mux { r := {{.}}; r.Use(zenchi.GetMiddleware()); return r }()`,
		},
		{
			ID:        "chi.NewRouter",
			MatchCall: "github.com/go-chi/chi/v5.NewRouter",
			Imports: map[string]string{
				"zenchi": "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi",
			},
			WrapTmpl: `func() *chi.Mux { r := {{.}}; r.Use(zenchi.GetMiddleware()); return r }()`,
		},
	}
}

// testGinRules returns rules for testing gin instrumentation
func testGinRules() []WrapRule {
	return []WrapRule{
		{
			ID:        "gin.Default",
			MatchCall: "github.com/gin-gonic/gin.Default",
			Imports: map[string]string{
				"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
			},
			WrapTmpl: `func() *gin.Engine { e := {{.}}; e.Use(zengin.GetMiddleware()); return e }()`,
		},
		{
			ID:        "gin.New",
			MatchCall: "github.com/gin-gonic/gin.New",
			Imports: map[string]string{
				"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
			},
			WrapTmpl: `func() *gin.Engine { e := {{.}}; e.Use(zengin.GetMiddleware()); return e }()`,
		},
	}
}

func TestInstrumentFile_ChiNewRouter(t *testing.T) {
	src := `package main

import "github.com/go-chi/chi/v5"

func main() {
	r := chi.NewRouter()
	r.Get("/", nil)
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testChiRules()})
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "zenchi")
	assert.Equal(t, "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi", result.Imports["zenchi"])

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "GetMiddleware()")
	assert.Contains(t, resultStr, "r.Use(zenchi.")
}

func TestInstrumentFile_ChiNewMux(t *testing.T) {
	src := `package main

import "github.com/go-chi/chi/v5"

func main() {
	r := chi.NewMux()
	r.Get("/", nil)
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testChiRules()})
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "zenchi")

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "GetMiddleware()")
}

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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, string(result.Code), "GetMiddleware()")
}

func TestInstrumentFile_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "nonexistent.go")

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst := NewInstrumentorWithRules(&InstrumentationRules{WrapRules: testGinRules()})
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

	inst, err := NewInstrumentor()
	require.NoError(t, err)

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

func TestInstrumentFile_PrependRule(t *testing.T) {
	src := `package sql

import "context"

type DB struct{}

func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*Rows, error) {
	return nil, nil
}

type Rows struct{}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "db.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	prependRules := []PrependRule{
		{
			ID:           "sql.DB.QueryContext",
			ReceiverType: "*database/sql.DB",
			FuncNames:    []string{"QueryContext"},
			Imports: map[string]string{
				"sink": "github.com/example/sink",
			},
			PrependTmpl: `if err := sink.Check({{ .Function.Argument 0 }}, {{ .Function.Argument 1 }}); err != nil {
	return nil, err
}`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "database/sql")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "sink")

	resultStr := string(result.Code)
	// Go printer may add newlines, so check for the key parts
	assert.Contains(t, resultStr, "sink.Check(ctx, query")
	assert.Contains(t, resultStr, "return nil, err")
	assert.Contains(t, resultStr, "import")
}

func TestInstrumentFile_PrependRule_NoMatch(t *testing.T) {
	src := `package main

func DoSomething() {
	// Not a method with receiver
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	prependRules := []PrependRule{
		{
			ID:           "sql.DB.QueryContext",
			ReceiverType: "*database/sql.DB",
			FuncNames:    []string{"QueryContext"},
			Imports:      map[string]string{},
			PrependTmpl:  `// prepended`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "main")

	require.NoError(t, err)
	assert.False(t, result.Modified)
}

func TestInstrumentFile_PrependRule_MultipleFunctions(t *testing.T) {
	// Test that a single rule can match multiple function names (one-of)
	src := `package exec

import "context"

type Cmd struct {
	ctx context.Context
}

func (c *Cmd) Run() error {
	return nil
}

func (c *Cmd) Start() error {
	return nil
}

func (c *Cmd) Wait() error {
	return nil
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "cmd.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	// Single rule that matches both Run and Start, but not Wait
	prependRules := []PrependRule{
		{
			ID:           "exec.Cmd.RunOrStart",
			ReceiverType: "*os/exec.Cmd",
			FuncNames:    []string{"Run", "Start"}, // one-of
			Imports:      map[string]string{},
			PrependTmpl:  `_ = "instrumented"`, // Use actual statement, not just comment
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "os/exec")

	require.NoError(t, err)
	assert.True(t, result.Modified)

	resultStr := string(result.Code)
	// Should have instrumented both Run and Start
	assert.Equal(t, 2, strings.Count(resultStr, `"instrumented"`))
}

func TestInstrumentFile_PrependRule_StandaloneFunction(t *testing.T) {
	src := `package os

func OpenFile(name string, flag int, perm uint32) (*File, error) {
	return nil, nil
}

type File struct{}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "file.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	prependRules := []PrependRule{
		{
			ID:        "os.OpenFile",
			Package:   "os",
			FuncNames: []string{"OpenFile"},
			Imports: map[string]string{
				"sink": "github.com/example/sink",
			},
			PrependTmpl: `if err := sink.Check({{ .Function.Argument 0 }}); err != nil { return nil, err }`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "os")

	require.NoError(t, err)
	assert.True(t, result.Modified)
	assert.Contains(t, result.Imports, "sink")

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "sink.Check(name)")
	assert.Contains(t, resultStr, "return nil, err")
}

func TestInstrumentFile_PrependRule_StandaloneFunction_WrongPackage(t *testing.T) {
	src := `package main

func OpenFile(name string) error {
	return nil
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	prependRules := []PrependRule{
		{
			ID:          "os.OpenFile",
			Package:     "os", // Rule targets "os" package
			FuncNames:   []string{"OpenFile"},
			Imports:     map[string]string{},
			PrependTmpl: `// prepended`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "main") // Compiling "main" package

	require.NoError(t, err)
	assert.False(t, result.Modified)
}

func TestInstrumentFile_PrependRule_MethodNotMatchedByStandaloneFuncRule(t *testing.T) {
	src := `package os

type File struct{}

func (f *File) OpenFile(name string) error {
	return nil
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "file.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	prependRules := []PrependRule{
		{
			ID:          "os.OpenFile",
			Package:     "os", // Standalone function rule
			FuncNames:   []string{"OpenFile"},
			Imports:     map[string]string{},
			PrependTmpl: `// prepended`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{PrependRules: prependRules})
	result, err := inst.InstrumentFile(tmpFile, "os")

	require.NoError(t, err)
	// Should NOT match because OpenFile is a method, not a standalone function
	assert.False(t, result.Modified)
}

func TestInstrumentFile_InjectDeclRule(t *testing.T) {
	src := `package os

func Getpid() int {
	return 0
}

func OpenFile(name string) error {
	return nil
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "proc.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	injectDeclRules := []InjectDeclRule{
		{
			ID:         "os.linkname",
			Package:    "os",
			AnchorFunc: "Getpid",
			Links:      []string{"github.com/example/sink"},
			DeclTemplate: `//go:linkname __example_check github.com/example/sink.Check
func __example_check(string) error`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{InjectDeclRules: injectDeclRules})
	result, err := inst.InstrumentFile(tmpFile, "os")

	require.NoError(t, err)
	assert.True(t, result.Modified)

	// Check that link dependency is added
	assert.Contains(t, result.LinkDeps, "github.com/example/sink")

	resultStr := string(result.Code)
	assert.Contains(t, resultStr, "go:linkname")
	assert.Contains(t, resultStr, "__example_check")
	assert.Contains(t, resultStr, `"unsafe"`)
}

func TestInstrumentFile_InjectDeclRule_NoAnchor(t *testing.T) {
	src := `package os

func SomeOtherFunc() {
}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "other.go")
	require.NoError(t, os.WriteFile(tmpFile, []byte(src), 0o600))

	injectDeclRules := []InjectDeclRule{
		{
			ID:           "os.linkname",
			Package:      "os",
			AnchorFunc:   "Getpid", // Not in this file
			Links:        []string{},
			DeclTemplate: `func __test() {}`,
		},
	}

	inst := NewInstrumentorWithRules(&InstrumentationRules{InjectDeclRules: injectDeclRules})
	result, err := inst.InstrumentFile(tmpFile, "os")

	require.NoError(t, err)
	assert.False(t, result.Modified)
}
