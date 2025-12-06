package internal

import (
	"go/ast"
	"go/token"
	"strconv"
)

func addImports(f *ast.File, imports map[string]string) {
	if len(imports) == 0 {
		return
	}

	var importDecl *ast.GenDecl
	for _, decl := range f.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			importDecl = gd
			break
		}
	}

	if importDecl == nil {
		importDecl = &ast.GenDecl{Tok: token.IMPORT}
		f.Decls = append([]ast.Decl{importDecl}, f.Decls...)
	}

	existing := make(map[string]bool)
	for _, spec := range importDecl.Specs {
		if is, ok := spec.(*ast.ImportSpec); ok {
			path, _ := strconv.Unquote(is.Path.Value)
			existing[path] = true
		}
	}

	for alias, path := range imports {
		if existing[path] {
			continue
		}
		spec := &ast.ImportSpec{
			Name: &ast.Ident{Name: alias},
			Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(path)},
		}
		importDecl.Specs = append(importDecl.Specs, spec)
	}

	if len(importDecl.Specs) > 1 {
		importDecl.Lparen = 1
	}
}
