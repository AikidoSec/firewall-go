package internal

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
)

func transformDeclsWrap(decls []ast.Decl, fset *token.FileSet, pkgName, funcName string, rule WrapRule, modified *bool, importsToAdd map[string]string) {
	for _, decl := range decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			transformStmtsWrap(fn.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
		}
	}
}

func transformStmtsWrap(stmts []ast.Stmt, fset *token.FileSet, pkgName, funcName string, rule WrapRule, modified *bool, importsToAdd map[string]string) {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			for i, rhs := range s.Rhs {
				if newExpr := tryTransformCall(rhs, fset, pkgName, funcName, rule, modified, importsToAdd); newExpr != nil {
					s.Rhs[i] = newExpr
				}
			}
		case *ast.ExprStmt:
			if newExpr := tryTransformCall(s.X, fset, pkgName, funcName, rule, modified, importsToAdd); newExpr != nil {
				s.X = newExpr
			}
		case *ast.ReturnStmt:
			for i, result := range s.Results {
				if newExpr := tryTransformCall(result, fset, pkgName, funcName, rule, modified, importsToAdd); newExpr != nil {
					s.Results[i] = newExpr
				}
			}
		case *ast.IfStmt:
			if s.Body != nil {
				transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
			}
			if s.Else != nil {
				if block, ok := s.Else.(*ast.BlockStmt); ok {
					transformStmtsWrap(block.List, fset, pkgName, funcName, rule, modified, importsToAdd)
				}
			}
		case *ast.ForStmt:
			if s.Body != nil {
				transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
			}
		case *ast.RangeStmt:
			if s.Body != nil {
				transformStmtsWrap(s.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
			}
		case *ast.SwitchStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CaseClause); ok {
						transformStmtsWrap(cc.Body, fset, pkgName, funcName, rule, modified, importsToAdd)
					}
				}
			}
		case *ast.SelectStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok {
						transformStmtsWrap(cc.Body, fset, pkgName, funcName, rule, modified, importsToAdd)
					}
				}
			}
		case *ast.BlockStmt:
			transformStmtsWrap(s.List, fset, pkgName, funcName, rule, modified, importsToAdd)
		}
	}
}

func tryTransformCall(expr ast.Expr, fset *token.FileSet, pkgName, funcName string, rule WrapRule, modified *bool, importsToAdd map[string]string) ast.Expr {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != pkgName || sel.Sel.Name != funcName {
		return nil
	}

	var origBuf bytes.Buffer
	printer.Fprint(&origBuf, fset, call)
	origCode := origBuf.String()

	wrapped := strings.Replace(rule.WrapTmpl, "{{.}}", origCode, 1)

	wrappedExpr, err := parser.ParseExpr(wrapped)
	if err != nil {
		return nil
	}

	*modified = true
	for alias, path := range rule.Imports {
		importsToAdd[alias] = path
	}

	return wrappedExpr
}
