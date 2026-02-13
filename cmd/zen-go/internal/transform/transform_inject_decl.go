package transform

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// TransformDeclsInjectDecl injects declarations (like go:linkname) into a file.
// The declaration is inserted immediately before the anchor function.
func TransformDeclsInjectDecl(f *ast.File, fset *token.FileSet, rule rules.InjectDeclRule, modified *bool, linksToAdd *[]string) error {
	anchorIndex := findAnchorFunction(f, rule.AnchorFunc)
	if anchorIndex == -1 {
		return nil // Anchor function not found, skip
	}

	// Parse the declaration template with comments
	// We need to add "unsafe" import for go:linkname to work
	declCode := `package p
		import _ "unsafe"
	` + rule.DeclTemplate

	declFile, err := parser.ParseFile(fset, "", declCode, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse inject decl template for %s: %w", rule.ID, err)
	}

	// Extract declarations to inject (skip import)
	var declsToInject []ast.Decl
	for _, decl := range declFile.Decls {
		// Skip the import declaration, we'll handle that separately
		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.IMPORT {
			continue
		}
		declsToInject = append(declsToInject, decl)
	}

	if len(declsToInject) == 0 {
		return errors.New("no declarations found in template")
	}

	// Copy go:linkname directive comments to the target file.
	// Go's AST stores comments separately from declarations, so we must
	// explicitly add them to f.Comments or they'll be lost in the output.
	for _, decl := range declsToInject {
		for _, cg := range declFile.Comments {
			// Check if comment is immediately before this declaration
			if decl.Pos() > cg.Pos() && decl.Pos()-cg.End() < 100 {
				f.Comments = append(f.Comments, cg)
			}
		}
	}

	// Insert declarations right before the anchor function
	newDecls := make([]ast.Decl, 0, len(f.Decls)+len(declsToInject))
	newDecls = append(newDecls, f.Decls[:anchorIndex]...)
	newDecls = append(newDecls, declsToInject...)
	newDecls = append(newDecls, f.Decls[anchorIndex:]...)
	f.Decls = newDecls

	// Add unsafe import (required for go:linkname)
	addUnsafeImport(f)

	*modified = true
	*linksToAdd = append(*linksToAdd, rule.Links...)

	return nil
}

func findAnchorFunction(f *ast.File, anchor string) int {
	anchorIndex := -1
	for i, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == anchor {
			anchorIndex = i
			break
		}
	}

	return anchorIndex
}

// addUnsafeImport adds an import for "unsafe" package if not already present.
// This is required for go:linkname directives.
func addUnsafeImport(f *ast.File) {
	// Check if unsafe is already imported
	for _, imp := range f.Imports {
		if imp.Path.Value == `"unsafe"` {
			return
		}
	}

	// Find or create an import declaration
	var importDecl *ast.GenDecl
	for _, decl := range f.Decls {
		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.IMPORT {
			importDecl = genDecl
			break
		}
	}

	unsafeSpec := &ast.ImportSpec{
		Name: ast.NewIdent("_"),
		Path: &ast.BasicLit{
			Kind:  token.STRING,
			Value: `"unsafe"`,
		},
	}

	if importDecl != nil {
		importDecl.Specs = append(importDecl.Specs, unsafeSpec)
	} else {
		// Create new import declaration
		newImport := &ast.GenDecl{
			Tok:   token.IMPORT,
			Specs: []ast.Spec{unsafeSpec},
		}
		f.Decls = append([]ast.Decl{newImport}, f.Decls...)
	}
}
