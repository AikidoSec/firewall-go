package transform

import (
	"go/ast"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// getStructFields returns the fields of the named struct, or nil if not found.
func getStructFields(t *testing.T, f *ast.File, name string) []*ast.Field {
	t.Helper()
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				continue
			}
			if st, ok := ts.Type.(*ast.StructType); ok {
				return st.Fields.List
			}
		}
	}
	return nil
}

func TestTransformDeclsAddField_AddsField(t *testing.T) {
	src := `package main
type MyStruct struct {
	Existing string
}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.add.field",
		Package:    "main",
		StructName: "MyStruct",
		NewFields:  []rules.StructFieldDef{{Name: "NewField", Type: "string"}},
	}

	modified := false
	err := TransformDeclsAddField(f.Decls, fset, "main", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.True(t, modified)

	fields := getStructFields(t, f, "MyStruct")
	require.Len(t, fields, 2)
	assert.Equal(t, "Existing", fields[0].Names[0].Name)
	assert.Equal(t, "NewField", fields[1].Names[0].Name)
}

func TestTransformDeclsAddField_AddsMultipleFields(t *testing.T) {
	src := `package main
type MyStruct struct{}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.add.fields",
		Package:    "main",
		StructName: "MyStruct",
		NewFields: []rules.StructFieldDef{
			{Name: "FieldA", Type: "int"},
			{Name: "FieldB", Type: "bool"},
		},
	}

	modified := false
	err := TransformDeclsAddField(f.Decls, fset, "main", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.True(t, modified)

	fields := getStructFields(t, f, "MyStruct")
	require.Len(t, fields, 2)
	assert.Equal(t, "FieldA", fields[0].Names[0].Name)
	assert.Equal(t, "FieldB", fields[1].Names[0].Name)
}

func TestTransformDeclsAddField_WrongPackage_NoModification(t *testing.T) {
	src := `package other
type MyStruct struct{}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.wrong.pkg",
		Package:    "main",
		StructName: "MyStruct",
		NewFields:  []rules.StructFieldDef{{Name: "F", Type: "string"}},
	}

	modified := false
	err := TransformDeclsAddField(f.Decls, fset, "other", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
	assert.Empty(t, getStructFields(t, f, "MyStruct"))
}

func TestTransformDeclsAddField_StructNotFound_NoModification(t *testing.T) {
	src := `package main
type OtherStruct struct{}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.not.found",
		Package:    "main",
		StructName: "MyStruct",
		NewFields:  []rules.StructFieldDef{{Name: "F", Type: "string"}},
	}

	modified := false
	err := TransformDeclsAddField(f.Decls, fset, "main", rule, &modified, map[string]string{})
	require.NoError(t, err)
	assert.False(t, modified)
}

func TestTransformDeclsAddField_AddsImports(t *testing.T) {
	src := `package main
type MyStruct struct{}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.imports",
		Package:    "main",
		StructName: "MyStruct",
		NewFields:  []rules.StructFieldDef{{Name: "Ctx", Type: "context.Context"}},
		Imports:    map[string]string{"context": "context"},
	}

	importsToAdd := map[string]string{}
	err := TransformDeclsAddField(f.Decls, fset, "main", rule, new(bool), importsToAdd)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"context": "context"}, importsToAdd)
}

func TestTransformDeclsAddField_InvalidFieldType_Error(t *testing.T) {
	src := `package main
type MyStruct struct{}
`
	f, fset := parseFile(t, src)
	rule := rules.StructFieldRule{
		ID:         "test.invalid",
		Package:    "main",
		StructName: "MyStruct",
		NewFields:  []rules.StructFieldDef{{Name: "F", Type: "not a valid type!!!"}},
	}

	err := TransformDeclsAddField(f.Decls, fset, "main", rule, new(bool), map[string]string{})
	require.Error(t, err)
}

func TestParseStructField(t *testing.T) {
	t.Run("SimpleType", func(t *testing.T) {
		fset := token.NewFileSet()
		field, err := parseStructField(fset, "Name", "string")
		require.NoError(t, err)
		require.Len(t, field.Names, 1)
		assert.Equal(t, "Name", field.Names[0].Name)
	})

	t.Run("QualifiedType", func(t *testing.T) {
		fset := token.NewFileSet()
		field, err := parseStructField(fset, "Ctx", "context.Context")
		require.NoError(t, err)
		require.Len(t, field.Names, 1)
		assert.Equal(t, "Ctx", field.Names[0].Name)
	})

	t.Run("PointerType", func(t *testing.T) {
		fset := token.NewFileSet()
		field, err := parseStructField(fset, "Next", "*http.Request")
		require.NoError(t, err)
		require.Len(t, field.Names, 1)
		assert.Equal(t, "Next", field.Names[0].Name)
	})

	t.Run("InvalidType_Error", func(t *testing.T) {
		fset := token.NewFileSet()
		_, err := parseStructField(fset, "F", "not valid!!!")
		require.Error(t, err)
	})
}
