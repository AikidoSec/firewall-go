package transform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFunc(t *testing.T, src string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	require.NoError(t, err)
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn
		}
	}
	t.Fatal("no FuncDecl found in source")
	return nil
}

func TestDot_Function(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	d := &dot{fn: fn}
	assert.NotNil(t, d.Function())
}

func TestFunction_Name(t *testing.T) {
	fn := parseFunc(t, `package p; func MyFunc() {}`)
	f := &function{fn: fn}
	assert.Equal(t, "MyFunc", f.Name())
}

func TestFunction_Argument(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo(ctx int, query string, extra bool) {}`)
	f := &function{fn: fn}

	assert.Equal(t, "ctx", f.Argument(0))
	assert.Equal(t, "query", f.Argument(1))
	assert.Equal(t, "extra", f.Argument(2))
	assert.Equal(t, "", f.Argument(3))
	assert.Equal(t, "", f.Argument(-1))
}

func TestFunction_Argument_GroupedParams(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo(a, b string) {}`)
	f := &function{fn: fn}

	assert.Equal(t, "a", f.Argument(0))
	assert.Equal(t, "b", f.Argument(1))
}

func TestFunction_Argument_NoParams(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	f := &function{fn: fn}
	assert.Equal(t, "", f.Argument(0))
}

func TestFunction_Argument_UnnamedParam(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo(_ string) {}`)
	f := &function{fn: fn}
	assert.Equal(t, "_", f.Argument(0))
}

func TestFunction_Receiver(t *testing.T) {
	fn := parseFunc(t, `package p; type T struct{}; func (db *T) Foo() {}`)
	f := &function{fn: fn}
	assert.Equal(t, "db", f.Receiver())
}

func TestFunction_Receiver_NoReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; func Foo() {}`)
	f := &function{fn: fn}
	assert.Equal(t, "", f.Receiver())
}

func TestFunction_Receiver_UnnamedReceiver(t *testing.T) {
	fn := parseFunc(t, `package p; type T struct{}; func (*T) Foo() {}`)
	f := &function{fn: fn}
	assert.Equal(t, "", f.Receiver())
}
