package transform

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// TransformDeclsWrap walks through all declarations in a file looking for function
// declarations, then recursively transforms any matching function calls within them.
func TransformDeclsWrap(decls []ast.Decl, fset *token.FileSet, pkgName, funcName string, rule rules.WrapRule, modified *bool, importsToAdd map[string]string) error {
	for _, decl := range decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			err := transformStmtsWrap(fn.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// transformStmtsWrap recursively walks the statement tree, finding all expressions
// that might contain function calls and attempting to transform them.
//
// It handles:
// - Assignments (x := pkg.Func())
// - Expression statements (pkg.Func())
// - Return statements (return pkg.Func())
// - Control flow blocks (if/for/switch/select bodies)
func transformStmtsWrap(stmts []ast.Stmt, fset *token.FileSet, pkgName, funcName string, rule rules.WrapRule, modified *bool, importsToAdd map[string]string) error {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			for i, rhs := range s.Rhs {
				newExpr, err := tryTransformCall(rhs, fset, pkgName, funcName, rule, modified, importsToAdd)
				if err != nil {
					return err
				}

				if newExpr != nil {
					s.Rhs[i] = newExpr
				}
			}
		case *ast.ExprStmt:
			newExpr, err := tryTransformCall(s.X, fset, pkgName, funcName, rule, modified, importsToAdd)
			if err != nil {
				return err
			}

			if newExpr != nil {
				s.X = newExpr
			}
		case *ast.ReturnStmt:
			for i, result := range s.Results {
				newExpr, err := tryTransformCall(result, fset, pkgName, funcName, rule, modified, importsToAdd)
				if err != nil {
					return err
				}

				if newExpr != nil {
					s.Results[i] = newExpr
				}
			}
		case *ast.IfStmt:
			if s.Body != nil {
				err := transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
				if err != nil {
					return err
				}
			}
			if s.Else != nil {
				if block, ok := s.Else.(*ast.BlockStmt); ok {
					err := transformStmtsWrap(block.List, fset, pkgName, funcName, rule, modified, importsToAdd)
					if err != nil {
						return err
					}
				}
			}
		case *ast.ForStmt:
			if s.Body != nil {
				err := transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
				if err != nil {
					return err
				}
			}
		case *ast.RangeStmt:
			if s.Body != nil {
				err := transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
				if err != nil {
					return err
				}
			}
		case *ast.SwitchStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CaseClause); ok {
						err := transformStmtsWrap(cc.Body, fset, pkgName, funcName, rule, modified, importsToAdd)
						if err != nil {
							return err
						}
					}
				}
			}
		case *ast.SelectStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok {
						err := transformStmtsWrap(cc.Body, fset, pkgName, funcName, rule, modified, importsToAdd)
						if err != nil {
							return err
						}
					}
				}
			}
		case *ast.BlockStmt:
			err := transformStmtsWrap(s.List, fset, pkgName, funcName, rule, modified, importsToAdd)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// tryTransformCall attempts to transform a function call expression that matches
// the target package and function name by wrapping it according to the rule.
//
// AST Navigation:
//   - We're looking for expressions like: pkgName.funcName(args...)
//   - In Go's AST, this is represented as:
//     CallExpr { Fun: SelectorExpr { X: Ident(pkgName), Sel: Ident(funcName) } }
//
// Process:
// 1. Check if expr is a CallExpr (a function call)
// 2. Check if the function being called is a SelectorExpr (e.g., pkg.Func)
// 3. Verify the selector's receiver is an Ident matching our target package
// 4. Verify the selector's field matches our target function
// 5. If all match, wrap the call using the rule's template
//
// Returns the wrapped expression if transformation occurred, nil otherwise.
func tryTransformCall(expr ast.Expr, fset *token.FileSet, pkgName, funcName string, rule rules.WrapRule, modified *bool, importsToAdd map[string]string) (ast.Expr, error) {
	// Step 1: Check if this is a function call at all
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	// Step 2: Check if the call is in the form "something.method()"
	// (as opposed to just "function()")
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}

	// Step 3: Check package and func name match
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != pkgName || sel.Sel.Name != funcName {
		return nil, nil
	}

	// Step 4: Serialize the original call expression back to source code
	// e.g., AST for "http.Get(url)" becomes the string "http.Get(url)"
	var origBuf bytes.Buffer
	_ = printer.Fprint(&origBuf, fset, call)
	origCode := origBuf.String()

	// Step 5: Apply the wrapping template
	// e.g., if template is "instrument.Wrap({{.}})", we get "instrument.Wrap(http.Get(url))"
	wrapped := strings.Replace(rule.WrapTmpl, "{{.}}", origCode, 1)

	// Step 6: Parse the wrapped string back into an AST expression
	wrappedExpr, err := parser.ParseExpr(wrapped)
	if err != nil {
		return nil, err
	}

	// Step 7: Mark that we modified the file and register any new imports needed
	*modified = true
	for alias, path := range rule.Imports {
		importsToAdd[alias] = path
	}

	return wrappedExpr, nil
}
