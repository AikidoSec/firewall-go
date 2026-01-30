package internal

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"text/template"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// transformDeclsPrepend finds function declarations matching the prepend rule
// and prepends statements to the function body.
// Supports both methods (with receiver) and standalone functions (without receiver).
func transformDeclsPrepend(decls []ast.Decl, compilingPkg string, rule rules.PrependRule, modified *bool, importsToAdd map[string]string) error {
	for _, decl := range decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		// Check if function name matches any of the rule's function names
		if !matchesFuncName(fn.Name.Name, rule.FuncNames) {
			continue
		}

		// Determine if this rule matches methods or standalone functions
		switch {
		case rule.ReceiverType != "":
			// Rule is for methods, so must have a receiver
			if fn.Recv == nil {
				continue
			}
			if !matchesReceiverType(fn.Recv, compilingPkg, rule.ReceiverType) {
				continue
			}
		case rule.Package != "":
			// Rule is for standalone functions, so must NOT have a receiver
			// and must be compiling the target package
			if fn.Recv != nil {
				continue
			}
			if rule.Package != compilingPkg {
				continue
			}
		default:
			// No receiver type or package specified, so skip
			continue
		}

		// Build the prepend code by substituting function arguments
		prependCode, err := substituteArguments(rule.PrependTmpl, fn)
		if err != nil {
			return err
		}

		// Parse the prepend statements
		prependStmts, err := parseStatements(prependCode)
		if err != nil {
			return err
		}

		// Prepend the statements to the function body
		fn.Body.List = append(prependStmts, fn.Body.List...)

		*modified = true
		for alias, path := range rule.Imports {
			importsToAdd[alias] = path
		}
	}

	return nil
}

// matchesFuncName checks if a function name matches any in the list
func matchesFuncName(name string, funcNames []string) bool {
	return slices.Contains(funcNames, name)
}

// matchesReceiverType checks if a function's receiver matches the expected type
func matchesReceiverType(recv *ast.FieldList, compilingPkg, expectedType string) bool {
	if recv == nil || len(recv.List) == 0 {
		return false
	}

	recvField := recv.List[0]
	recvType := formatReceiverType(recvField.Type, compilingPkg)

	return recvType == expectedType
}

// formatReceiverType formats a receiver type expression as a string
// e.g. *database/sql.DB, package.Type
func formatReceiverType(expr ast.Expr, compilingPkg string) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		inner := formatReceiverType(t.X, compilingPkg)
		return "*" + inner
	case *ast.Ident:
		// Local type - prefix with current package
		return compilingPkg + "." + t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	}
	return ""
}

// substituteArguments replaces {{ .Function.Argument N }} with actual parameter names
func substituteArguments(tmpl string, fn *ast.FuncDecl) (string, error) {
	t, err := template.New("tmpl").Parse(tmpl)
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}
	err = t.Execute(buf, &dot{
		fn: fn,
	})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// parseStatements parses a string containing Go statements
func parseStatements(code string) ([]ast.Stmt, error) {
	// Wrap in a function to parse as statements
	wrapped := "package p\nfunc _() {\n" + code + "\n}"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", wrapped, 0)
	if err != nil {
		return nil, err
	}

	// Extract the statements from the function body
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn.Body.List, nil
		}
	}

	return nil, fmt.Errorf("failed to parse statements")
}
