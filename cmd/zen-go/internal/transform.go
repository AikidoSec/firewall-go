package internal

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"regexp"
	"strings"
)

// transformDeclsWrap walks through all declarations in a file looking for function
// declarations, then recursively transforms any matching function calls within them.
func transformDeclsWrap(decls []ast.Decl, fset *token.FileSet, pkgName, funcName string, rule WrapRule, modified *bool, importsToAdd map[string]string) {
	for _, decl := range decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			transformStmtsWrap(fn.Body.List, fset, pkgName, funcName, rule, modified, importsToAdd)
		}
	}
}

// transformStmtsWrap recursively walks the statement tree, finding all expressions
// that might contain function calls and attempting to transform them.
//
// It handles:
// - Assignments (x := pkg.Func())
// - Expression statements (pkg.Func())
// - Return statements (return pkg.Func())
// - Control flow blocks (if/for/switch/select bodies)
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
func tryTransformCall(expr ast.Expr, fset *token.FileSet, pkgName, funcName string, rule WrapRule, modified *bool, importsToAdd map[string]string) ast.Expr {
	// Step 1: Check if this is a function call at all
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}

	// Step 2: Check if the call is in the form "something.method()"
	// (as opposed to just "function()")
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	// Step 3: Check if "something" is a simple identifier (package name)
	// This ensures we're dealing with pkgName.funcName, not x.y.z.funcName
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != pkgName || sel.Sel.Name != funcName {
		return nil
	}

	// Step 4: Serialize the original call expression back to source code
	// e.g., "http.Get(url)" becomes the string "http.Get(url)"
	var origBuf bytes.Buffer
	printer.Fprint(&origBuf, fset, call)
	origCode := origBuf.String()

	// Step 5: Apply the wrapping template
	// e.g., if template is "instrument.Wrap({{.}})", we get "instrument.Wrap(http.Get(url))"
	wrapped := strings.Replace(rule.WrapTmpl, "{{.}}", origCode, 1)

	// Step 6: Parse the wrapped string back into an AST expression
	wrappedExpr, err := parser.ParseExpr(wrapped)
	if err != nil {
		return nil
	}

	// Step 7: Mark that we modified the file and register any new imports needed
	*modified = true
	for alias, path := range rule.Imports {
		importsToAdd[alias] = path
	}

	return wrappedExpr
}

// transformDeclsPrepend finds function declarations matching the prepend rule
// and prepends statements to the function body
func transformDeclsPrepend(decls []ast.Decl, compilingPkg string, rule PrependRule, modified *bool, importsToAdd map[string]string) {
	for _, decl := range decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv == nil {
			continue
		}

		// Check if function name matches
		if fn.Name.Name != rule.FuncName {
			continue
		}

		// Check if receiver type matches
		if !matchesReceiverType(fn.Recv, compilingPkg, rule.ReceiverType) {
			continue
		}

		// Build the prepend code by substituting function arguments
		prependCode := substituteArguments(rule.PrependTmpl, fn)

		// Parse the prepend statements
		prependStmts, err := parseStatements(prependCode)
		if err != nil {
			continue
		}

		// Prepend the statements to the function body
		fn.Body.List = append(prependStmts, fn.Body.List...)

		*modified = true
		for alias, path := range rule.Imports {
			importsToAdd[alias] = path
		}
	}
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
func substituteArguments(template string, fn *ast.FuncDecl) string {
	result := template

	// Match {{ .Function.Argument N }} or {{.Function.Argument N}}
	re := regexp.MustCompile(`\{\{\s*\.Function\.Argument\s+(\d+)\s*\}\}`)

	result = re.ReplaceAllStringFunc(result, func(match string) string {
		// Extract the argument index
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return match
		}

		var idx int
		_, err := fmt.Sscanf(submatches[1], "%d", &idx)
		if err != nil {
			return ""
		}

		// Get the parameter name at that index
		paramName := getParamName(fn, idx)
		if paramName == "" {
			return match
		}

		return paramName
	})

	return result
}

// getParamName returns the name of the parameter at the given index
func getParamName(fn *ast.FuncDecl, idx int) string {
	if fn.Type.Params == nil {
		return ""
	}

	paramIdx := 0
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if paramIdx == idx {
				return name.Name
			}
			paramIdx++
		}
		// Handle unnamed parameters (shouldn't happen for methods we instrument)
		if len(field.Names) == 0 {
			if paramIdx == idx {
				return ""
			}
			paramIdx++
		}
	}

	return ""
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
