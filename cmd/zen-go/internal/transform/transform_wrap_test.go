package transform

import (
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// requireWrappedCall asserts that expr is a call to wrapperPkg.wrapperFunc and returns
// the first argument, which should be the original (wrapped) call.
func requireWrappedCall(t *testing.T, expr ast.Expr, wrapperPkg, wrapperFunc string) *ast.CallExpr {
	t.Helper()
	call, ok := expr.(*ast.CallExpr)
	require.True(t, ok, "expected CallExpr")
	sel, ok := call.Fun.(*ast.SelectorExpr)
	require.True(t, ok, "expected SelectorExpr")
	assert.Equal(t, wrapperPkg, sel.X.(*ast.Ident).Name)
	assert.Equal(t, wrapperFunc, sel.Sel.Name)
	require.Len(t, call.Args, 1)
	inner, ok := call.Args[0].(*ast.CallExpr)
	require.True(t, ok, "expected inner CallExpr as argument")
	return inner
}

func TestTransformDeclsWrap_InAssignment(t *testing.T) {
	src := `package p
func main() { r := gin.Default(); _ = r }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{
		WrapTmpl: `mw.Wrap({{.}})`,
		Imports:  map[string]string{"mw": "example.com/mw"},
	}

	modified := false
	importsToAdd := map[string]string{}
	err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, &modified, importsToAdd)
	require.NoError(t, err)

	assert.True(t, modified)
	assert.Equal(t, "example.com/mw", importsToAdd["mw"])

	fn := findFunc(t, f.Decls, "main")
	assign, ok := fn.Body.List[0].(*ast.AssignStmt)
	require.True(t, ok)
	inner := requireWrappedCall(t, assign.Rhs[0], "mw", "Wrap")
	origSel := inner.Fun.(*ast.SelectorExpr)
	assert.Equal(t, "gin", origSel.X.(*ast.Ident).Name)
	assert.Equal(t, "Default", origSel.Sel.Name)
}

func TestTransformDeclsWrap_InExprStmt(t *testing.T) {
	src := `package p
func main() { gin.Default() }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

	modified := false
	err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, &modified, map[string]string{})
	require.NoError(t, err)

	assert.True(t, modified)

	fn := findFunc(t, f.Decls, "main")
	exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	require.True(t, ok)
	requireWrappedCall(t, exprStmt.X, "mw", "Wrap")
}

func TestTransformDeclsWrap_InReturn(t *testing.T) {
	src := `package p
func get() interface{} { return gin.Default() }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

	modified := false
	err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, &modified, map[string]string{})
	require.NoError(t, err)

	assert.True(t, modified)

	fn := findFunc(t, f.Decls, "get")
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	require.True(t, ok)
	requireWrappedCall(t, ret.Results[0], "mw", "Wrap")
}

func TestTransformDeclsWrap_InControlFlow(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		getExpr func(fn *ast.FuncDecl) ast.Expr
	}{
		{
			name: "if body",
			src: `package p
func main() {
	if true {
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				return fn.Body.List[0].(*ast.IfStmt).Body.List[0].(*ast.AssignStmt).Rhs[0]
			},
		},
		{
			name: "else body",
			src: `package p
func main() {
	if false {
	} else {
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				return fn.Body.List[0].(*ast.IfStmt).Else.(*ast.BlockStmt).List[0].(*ast.AssignStmt).Rhs[0]
			},
		},
		{
			name: "for body",
			src: `package p
func main() {
	for i := 0; i < 1; i++ {
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				return fn.Body.List[0].(*ast.ForStmt).Body.List[0].(*ast.AssignStmt).Rhs[0]
			},
		},
		{
			name: "range body",
			src: `package p
func main() {
	s := []int{1}
	for range s {
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				return fn.Body.List[1].(*ast.RangeStmt).Body.List[0].(*ast.AssignStmt).Rhs[0]
			},
		},
		{
			name: "switch case",
			src: `package p
func main() {
	switch {
	case true:
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				cc := fn.Body.List[0].(*ast.SwitchStmt).Body.List[0].(*ast.CaseClause)
				return cc.Body[0].(*ast.AssignStmt).Rhs[0]
			},
		},
		{
			name: "select case",
			src: `package p
func main() {
	ch := make(chan int)
	select {
	case <-ch:
		r := gin.Default()
		_ = r
	}
}`,
			getExpr: func(fn *ast.FuncDecl) ast.Expr {
				cc := fn.Body.List[1].(*ast.SelectStmt).Body.List[0].(*ast.CommClause)
				return cc.Body[0].(*ast.AssignStmt).Rhs[0]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, fset := parseFile(t, tt.src)
			rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

			modified := false
			err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, &modified, map[string]string{})
			require.NoError(t, err)
			assert.True(t, modified)

			fn := findFunc(t, f.Decls, "main")
			requireWrappedCall(t, tt.getExpr(fn), "mw", "Wrap")
		})
	}
}

func TestTransformDeclsWrap_WrongPkg_NoMatch(t *testing.T) {
	src := `package p
func main() { r := gin.Default(); _ = r }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

	modified := false
	err := TransformDeclsWrap(f.Decls, fset, "http", "Default", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsWrap_WrongFunc_NoMatch(t *testing.T) {
	src := `package p
func main() { r := gin.Default(); _ = r }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

	modified := false
	err := TransformDeclsWrap(f.Decls, fset, "gin", "New", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsWrap_MultipleCalls(t *testing.T) {
	src := `package p
func main() {
	r1 := gin.Default()
	r2 := gin.Default()
	_ = r1
	_ = r2
}`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `mw.Wrap({{.}})`}

	modified := false
	err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, &modified, map[string]string{})
	require.NoError(t, err)

	assert.True(t, modified)

	fn := findFunc(t, f.Decls, "main")
	for _, stmt := range fn.Body.List[:2] {
		assign, ok := stmt.(*ast.AssignStmt)
		require.True(t, ok)
		requireWrappedCall(t, assign.Rhs[0], "mw", "Wrap")
	}
}

func TestTransformDeclsWrap_InvalidTemplate_Error(t *testing.T) {
	src := `package p
func main() { r := gin.Default(); _ = r }`
	f, fset := parseFile(t, src)
	rule := rules.WrapRule{WrapTmpl: `!!!invalid go {{.}}`}

	err := TransformDeclsWrap(f.Decls, fset, "gin", "Default", rule, new(bool), map[string]string{})
	require.Error(t, err)
}
