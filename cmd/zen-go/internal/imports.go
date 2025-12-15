package internal

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
)

type DuplicateImportAliasError struct {
	alias string
}

func (e *DuplicateImportAliasError) Error() string {
	return fmt.Sprintf("duplicate import alias: %s", e.alias)
}

func addImports(f *ast.File, imports map[string]string) error {
	if len(imports) == 0 {
		return nil
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

	existingAliases := make(map[string]string)
	for _, spec := range importDecl.Specs {
		if is, ok := spec.(*ast.ImportSpec); ok {
			path, _ := strconv.Unquote(is.Path.Value)
			if is.Name != nil {
				existingAliases[is.Name.String()] = path
			}
		}
	}

	for alias, path := range imports {
		if existingAliases[alias] != "" {
			// If the path is the same, then we're trying to import the same package with the same alias
			if existingAliases[alias] == path {
				continue
			}

			// If not, we're trying to use the same alias for different packages
			return &DuplicateImportAliasError{
				alias: alias,
			}
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

	return nil
}
