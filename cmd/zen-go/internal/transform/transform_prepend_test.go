package transform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

func parseDecls(t *testing.T, src string) []ast.Decl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	require.NoError(t, err)
	return f.Decls
}

func findFunc(t *testing.T, decls []ast.Decl, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("func %q not found in decls", name)
	return nil
}

func TestTransformDeclsPrepend_Method(t *testing.T) {
	src := `package sql
func (db *DB) QueryContext(ctx int, query string) error {
	return nil
}`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		ReceiverType: "*database/sql.DB",
		FuncNames:    []string{"QueryContext"},
		PrependTmpl:  `_ = sink.Check({{ .Function.Argument 0 }}, {{ .Function.Argument 1 }})`,
		Imports:      map[string]string{"sink": "example.com/sink"},
	}

	modified := false
	importsToAdd := map[string]string{}
	err := TransformDeclsPrepend(decls, "database/sql", rule, &modified, importsToAdd)
	require.NoError(t, err)

	assert.True(t, modified)
	assert.Equal(t, "example.com/sink", importsToAdd["sink"])

	fn := findFunc(t, decls, "QueryContext")
	require.Len(t, fn.Body.List, 2)

	// Verify the prepended statement: _ = sink.Check(ctx, query)
	assign, ok := fn.Body.List[0].(*ast.AssignStmt)
	require.True(t, ok, "expected assignment statement")
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	require.True(t, ok, "expected call expression")
	sel, ok := call.Fun.(*ast.SelectorExpr)
	require.True(t, ok, "expected selector expression")
	assert.Equal(t, "sink", sel.X.(*ast.Ident).Name)
	assert.Equal(t, "Check", sel.Sel.Name)
	require.Len(t, call.Args, 2)
	assert.Equal(t, "ctx", call.Args[0].(*ast.Ident).Name)
	assert.Equal(t, "query", call.Args[1].(*ast.Ident).Name)

	// Original body is still present
	_, ok = fn.Body.List[1].(*ast.ReturnStmt)
	assert.True(t, ok, "expected return statement as second statement")
}

func TestTransformDeclsPrepend_StandaloneFunction(t *testing.T) {
	src := `package os
func Getenv(key string) string {
	return ""
}`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "os",
		FuncNames:   []string{"Getenv"},
		PrependTmpl: `_ = check({{ .Function.Argument 0 }})`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "os", rule, &modified, map[string]string{})
	require.NoError(t, err)

	assert.True(t, modified)

	fn := findFunc(t, decls, "Getenv")
	require.Len(t, fn.Body.List, 2)

	// Verify argument substitution: check(key)
	assign, ok := fn.Body.List[0].(*ast.AssignStmt)
	require.True(t, ok)
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	require.True(t, ok)
	assert.Equal(t, "check", call.Fun.(*ast.Ident).Name)
	require.Len(t, call.Args, 1)
	assert.Equal(t, "key", call.Args[0].(*ast.Ident).Name)
}

func TestTransformDeclsPrepend_WrongPackage_NoMatch(t *testing.T) {
	src := `package os
func Getenv(key string) string { return "" }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "os",
		FuncNames:   []string{"Getenv"},
		PrependTmpl: `_ = check({{ .Function.Argument 0 }})`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "syscall", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_WrongFuncName_NoMatch(t *testing.T) {
	src := `package os
func Getenv(key string) string { return "" }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "os",
		FuncNames:   []string{"Setenv"},
		PrependTmpl: `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "os", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_WrongReceiverType_NoMatch(t *testing.T) {
	src := `package sql
func (db *DB) QueryContext(ctx int, query string) error { return nil }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		ReceiverType: "*database/sql.Tx",
		FuncNames:    []string{"QueryContext"},
		PrependTmpl:  `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "database/sql", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_NoReceiverOrPackage_NoMatch(t *testing.T) {
	src := `package p
func Foo() {}`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		FuncNames:   []string{"Foo"},
		PrependTmpl: `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "p", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_MultipleFuncNames(t *testing.T) {
	src := `package sql
func (db *DB) QueryContext(ctx int, query string) error { return nil }
func (db *DB) ExecContext(ctx int, query string) error { return nil }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		ReceiverType: "*database/sql.DB",
		FuncNames:    []string{"QueryContext", "ExecContext"},
		PrependTmpl:  `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "database/sql", rule, &modified, map[string]string{})
	require.NoError(t, err)

	assert.True(t, modified)
	assert.Len(t, findFunc(t, decls, "QueryContext").Body.List, 2)
	assert.Len(t, findFunc(t, decls, "ExecContext").Body.List, 2)
}

func TestTransformDeclsPrepend_SkipsNilBody(t *testing.T) {
	// Interface method declarations have no body.
	src := `package p
type I interface{ Foo() }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "p",
		FuncNames:   []string{"Foo"},
		PrependTmpl: `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "p", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_ReceiverRuleSkipsStandaloneFunc(t *testing.T) {
	src := `package sql
func QueryContext(ctx int, query string) error { return nil }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		ReceiverType: "*database/sql.DB",
		FuncNames:    []string{"QueryContext"},
		PrependTmpl:  `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "database/sql", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_StandaloneRuleSkipsMethod(t *testing.T) {
	src := `package sql
func (db *DB) QueryContext(ctx int, query string) error { return nil }`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "database/sql",
		FuncNames:   []string{"QueryContext"},
		PrependTmpl: `_ = check()`,
	}

	modified := false
	err := TransformDeclsPrepend(decls, "database/sql", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsPrepend_InvalidTemplate_Error(t *testing.T) {
	src := `package p
func Foo() {}`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "p",
		FuncNames:   []string{"Foo"},
		PrependTmpl: `{{ .Invalid syntax`,
	}

	err := TransformDeclsPrepend(decls, "p", rule, new(bool), map[string]string{})
	require.Error(t, err)
}

func TestTransformDeclsPrepend_InvalidGeneratedCode_Error(t *testing.T) {
	src := `package p
func Foo(x int) {}`
	decls := parseDecls(t, src)
	rule := rules.PrependRule{
		Package:     "p",
		FuncNames:   []string{"Foo"},
		PrependTmpl: `this is not valid go!!!`,
	}

	err := TransformDeclsPrepend(decls, "p", rule, new(bool), map[string]string{})
	require.Error(t, err)
}

func TestMatchesFuncName(t *testing.T) {
	assert.True(t, matchesFuncName("Foo", []string{"Foo", "Bar"}))
	assert.False(t, matchesFuncName("Baz", []string{"Foo", "Bar"}))
	assert.False(t, matchesFuncName("Foo", nil))
}

func TestFormatReceiverType_PointerReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; type DB struct{}; func (db *DB) M() {}`)
	got := formatReceiverType(fn.Recv.List[0].Type, "mypkg")
	assert.Equal(t, "*mypkg.DB", got)
}

func TestFormatReceiverType_ValueReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; type DB struct{}; func (db DB) M() {}`)
	got := formatReceiverType(fn.Recv.List[0].Type, "mypkg")
	assert.Equal(t, "mypkg.DB", got)
}
