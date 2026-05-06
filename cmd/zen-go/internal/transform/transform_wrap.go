package transform

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"

	"golang.org/x/tools/go/ast/astutil"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// TransformDeclsWrap walks all function declarations in a file and wraps any
// call matching pkgName.funcName with the given rule's template.
func TransformDeclsWrap(decls []ast.Decl, fset *token.FileSet, pkgName, funcName string, rule rules.WrapRule, modified *bool, importsToAdd map[string]string) error {
	for _, decl := range decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		var applyErr error
		astutil.Apply(fn.Body, func(c *astutil.Cursor) bool {
			call, ok := c.Node().(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != pkgName || sel.Sel.Name != funcName {
				return true
			}

			var origBuf bytes.Buffer
			_ = printer.Fprint(&origBuf, fset, call)

			wrapped := strings.Replace(rule.WrapTmpl, "{{.}}", origBuf.String(), 1)

			wrappedExpr, err := parser.ParseExpr(wrapped)
			if err != nil {
				applyErr = err
				return false
			}

			c.Replace(wrappedExpr)
			*modified = true
			for alias, path := range rule.Imports {
				importsToAdd[alias] = path
			}

			return false
		}, nil)

		if applyErr != nil {
			return applyErr
		}
	}

	return nil
}
