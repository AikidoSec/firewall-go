package internal

import (
	"go/ast"
)

// dot provides a set of methods to be used within the prepend templates
//
// For example, so you can get the names of the function arguments:
// e.g. {{ .Function.Argument 2 }}
type dot struct {
	fn *ast.FuncDecl
}

func (d *dot) Function() *function {
	return &function{
		fn: d.fn,
	}
}

type function struct {
	fn *ast.FuncDecl
}

// Argument returns the name of the argument at the index
func (f *function) Argument(idx int) string {
	if f.fn.Type.Params == nil {
		return ""
	}

	paramIdx := 0
	for _, field := range f.fn.Type.Params.List {
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
