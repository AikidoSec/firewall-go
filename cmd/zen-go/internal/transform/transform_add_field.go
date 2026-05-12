package transform

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

// TransformDeclsAddField finds struct type declarations matching the rule and appends new fields.
func TransformDeclsAddField(decls []ast.Decl, fset *token.FileSet, compilingPkg string, rule rules.StructFieldRule, modified *bool, importsToAdd map[string]string) error {
	if rule.Package != "" && rule.Package != compilingPkg {
		return nil
	}

	for _, decl := range decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != rule.StructName {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			for _, fd := range rule.NewFields {
				field, err := parseStructField(fset, fd.Name, fd.Type)
				if err != nil {
					return fmt.Errorf("rule %s: parsing field %q %q: %w", rule.ID, fd.Name, fd.Type, err)
				}
				structType.Fields.List = append(structType.Fields.List, field)
			}

			*modified = true
			for alias, path := range rule.Imports {
				importsToAdd[alias] = path
			}
		}
	}

	return nil
}

func parseStructField(fset *token.FileSet, name, typeExpr string) (*ast.Field, error) {
	src := fmt.Sprintf("package p\ntype _s struct { %s %s }", name, typeExpr)
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil, err
	}

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			if len(st.Fields.List) > 0 {
				return st.Fields.List[0], nil
			}
		}
	}

	return nil, fmt.Errorf("failed to extract field from parsed source")
}
