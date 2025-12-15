package internal

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddImports_NewImport(t *testing.T) {
	src := `package main

import "fmt"

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, `zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"`)
}

func TestAddImports_ExistingImport(t *testing.T) {
	src := `package main

import (
	"fmt"
	zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
)

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	// Should only appear once (not duplicated)
	count := strings.Count(result, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.Equal(t, 1, count)
}

func TestAddImports_NoImportDecl(t *testing.T) {
	src := `package main

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, `zengin "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"`)
}

func TestAddImports_MultipleImports(t *testing.T) {
	src := `package main

import "fmt"

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
		"zensql": "github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, "zengin")
	assert.Contains(t, result, "zensql")
}

func TestAddImports_EmptyMap(t *testing.T) {
	src := `package main

import "fmt"

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	originalDecls := len(f.Decls)
	err = addImports(f, map[string]string{})
	require.NoError(t, err)

	// Should not modify the file
	assert.Equal(t, originalDecls, len(f.Decls))
}

func TestAddImports_PreservesExistingImports(t *testing.T) {
	src := `package main

import (
	"fmt"
	"os"
)

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, `"fmt"`)
	assert.Contains(t, result, `"os"`)
	assert.Contains(t, result, "zengin")
}

func TestAddImports_GroupedImports(t *testing.T) {
	src := `package main

import "fmt"

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	// Check that import decl has Lparen set (grouped imports)
	var importDecl *ast.GenDecl
	for _, decl := range f.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			importDecl = gd
			break
		}
	}

	require.NotNil(t, importDecl)
	assert.True(t, importDecl.Lparen.IsValid(), "import should be grouped with parentheses")
}

func TestAddImports_ImportingSamePackageWithAnAlias(t *testing.T) {
	src := `package main

import (
	"fmt"
	"github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
)

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, "zengin")

	// It should leave the original import and add a new one
	count := strings.Count(result, "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin")
	assert.Equal(t, 2, count)
}

func TestAddImports_ImportingSamePackageWithDifferentAlias(t *testing.T) {
	src := `package main

import (
	"fmt"
	ginzen "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
)

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.NoError(t, err)

	var buf strings.Builder
	err = printer.Fprint(&buf, fset, f)
	require.NoError(t, err)

	result := buf.String()
	assert.Contains(t, result, "zengin")
	assert.Contains(t, result, "ginzen")
}

func TestAddImports_ConflictingImportAlias(t *testing.T) {
	src := `package main

import (
	"fmt"
	zengin "github.com/AikidoSec/firewall-go/gin"
)

func main() {}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	err = addImports(f, map[string]string{
		"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
	})
	require.Error(t, err)

	var duplicateErr *DuplicateImportAliasError
	require.ErrorAs(t, err, &duplicateErr)
}
