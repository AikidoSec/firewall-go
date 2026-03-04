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

func parseFile(t *testing.T, src string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)
	return f, fset
}

func hasUnsafeImport(t *testing.T, f *ast.File) bool {
	t.Helper()
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.IMPORT {
			continue
		}
		for _, spec := range genDecl.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if ok && imp.Path.Value == `"unsafe"` {
				return true
			}
		}
	}
	return false
}

func funcDeclIndex(f *ast.File, name string) int {
	for i, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return i
		}
	}
	return -1
}

func TestTransformDeclsInjectDecl_InjectsBeforeAnchor(t *testing.T) {
	src := `package os
func Other() {}
func Getpid() int { return 0 }
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		Links:        []string{"example.com/sink"},
		DeclTemplate: `func __injected() {}`,
	}

	modified := false
	var linksToAdd []string
	err := TransformDeclsInjectDecl(f, fset, rule, &modified, &linksToAdd)
	require.NoError(t, err)

	assert.True(t, modified)

	// __injected must appear immediately before Getpid
	injectedIdx := funcDeclIndex(f, "__injected")
	anchorIdx := funcDeclIndex(f, "Getpid")
	require.NotEqual(t, -1, injectedIdx, "__injected not found")
	require.NotEqual(t, -1, anchorIdx, "Getpid not found")
	assert.Equal(t, anchorIdx-1, injectedIdx, "__injected should be immediately before Getpid")
}

func TestTransformDeclsInjectDecl_AnchorNotFound_NoModification(t *testing.T) {
	src := `package os
func Other() {}
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		DeclTemplate: `func __injected() {}`,
	}

	modified := false
	var linksToAdd []string
	err := TransformDeclsInjectDecl(f, fset, rule, &modified, &linksToAdd)
	require.NoError(t, err)

	assert.False(t, modified)
	assert.Len(t, f.Decls, 1)
	assert.Empty(t, linksToAdd)
}

func TestTransformDeclsInjectDecl_LinksAppended(t *testing.T) {
	src := `package os
func Getpid() int { return 0 }
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		Links:        []string{"example.com/sink", "example.com/other"},
		DeclTemplate: `func __injected() {}`,
	}

	var linksToAdd []string
	err := TransformDeclsInjectDecl(f, fset, rule, new(bool), &linksToAdd)
	require.NoError(t, err)

	assert.Equal(t, []string{"example.com/sink", "example.com/other"}, linksToAdd)
}

func TestTransformDeclsInjectDecl_AddsUnsafeImport(t *testing.T) {
	src := `package os
func Getpid() int { return 0 }
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		DeclTemplate: `func __injected() {}`,
	}

	err := TransformDeclsInjectDecl(f, fset, rule, new(bool), &[]string{})
	require.NoError(t, err)

	assert.True(t, hasUnsafeImport(t, f))
}

func TestTransformDeclsInjectDecl_AnchorIsFirstDecl(t *testing.T) {
	src := `package os
func Getpid() int { return 0 }
func Other() {}
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		DeclTemplate: `func __injected() {}`,
	}

	err := TransformDeclsInjectDecl(f, fset, rule, new(bool), &[]string{})
	require.NoError(t, err)

	// __injected should be immediately before Getpid, which was at index 0
	injectedIdx := funcDeclIndex(f, "__injected")
	anchorIdx := funcDeclIndex(f, "Getpid")
	require.NotEqual(t, -1, injectedIdx)
	require.NotEqual(t, -1, anchorIdx)
	assert.Equal(t, anchorIdx-1, injectedIdx)
}

func TestTransformDeclsInjectDecl_InvalidTemplate_Error(t *testing.T) {
	src := `package os
func Getpid() int { return 0 }
`
	f, fset := parseFile(t, src)
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		DeclTemplate: `this is not valid go`,
	}

	err := TransformDeclsInjectDecl(f, fset, rule, new(bool), &[]string{})
	require.Error(t, err)
}

func TestTransformDeclsInjectDecl_EmptyTemplate_Error(t *testing.T) {
	src := `package os
func Getpid() int { return 0 }
`
	f, fset := parseFile(t, src)
	// A template with only an import produces no non-import decls.
	rule := rules.InjectDeclRule{
		AnchorFunc:   "Getpid",
		DeclTemplate: `import "fmt"`,
	}

	err := TransformDeclsInjectDecl(f, fset, rule, new(bool), &[]string{})
	require.Error(t, err)
}

// --- findAnchorFunction ---

func TestFindAnchorFunction_Found(t *testing.T) {
	src := `package p
func Foo() {}
func Bar() {}
func Baz() {}
`
	f, _ := parseFile(t, src)
	assert.Equal(t, 1, findAnchorFunction(f, "Bar"))
}

func TestFindAnchorFunction_FirstDecl(t *testing.T) {
	src := `package p
func Foo() {}
func Bar() {}
`
	f, _ := parseFile(t, src)
	assert.Equal(t, 0, findAnchorFunction(f, "Foo"))
}

func TestFindAnchorFunction_NotFound(t *testing.T) {
	src := `package p
func Foo() {}
`
	f, _ := parseFile(t, src)
	assert.Equal(t, -1, findAnchorFunction(f, "Missing"))
}

// --- addUnsafeImport ---

func TestAddUnsafeImport_AddsImport(t *testing.T) {
	src := `package p
import "fmt"
func Foo() {}
`
	f, _ := parseFile(t, src)
	assert.False(t, hasUnsafeImport(t, f))

	addUnsafeImport(f)

	assert.True(t, hasUnsafeImport(t, f))
}

func TestAddUnsafeImport_NoopWhenAlreadyPresent(t *testing.T) {
	src := `package p
import _ "unsafe"
func Foo() {}
`
	f, _ := parseFile(t, src)
	importsBefore := len(f.Imports)

	addUnsafeImport(f)

	assert.Equal(t, importsBefore, len(f.Imports))
}

func TestAddUnsafeImport_CreatesImportBlock(t *testing.T) {
	src := `package p
func Foo() {}
`
	f, _ := parseFile(t, src)
	assert.False(t, hasUnsafeImport(t, f))

	addUnsafeImport(f)

	assert.True(t, hasUnsafeImport(t, f))
}
