package transform

import (
	"fmt"
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

// Receiver returns the name of the receiver variable
func (f *function) Receiver() string {
	if f.fn.Recv == nil || len(f.fn.Recv.List) == 0 {
		return ""
	}
	field := f.fn.Recv.List[0]
	if len(field.Names) == 0 {
		return ""
	}
	return field.Names[0].Name
}

// Name returns the name of the function
func (f *function) Name() string {
	if f.fn.Name == nil {
		return ""
	}
	return f.fn.Name.Name
}

// Result returns the name of the return value at the given index.
// If the return value is unnamed, it assigns a synthetic name (_aikido_r<idx>)
// by modifying the AST. This enables defer blocks in prepend templates to
// capture return values via named returns.
func (f *function) Result(idx int) string {
	if f.fn.Type.Results == nil {
		return ""
	}

	resultIdx := 0
	for _, field := range f.fn.Type.Results.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}

		for i := 0; i < count; i++ {
			if resultIdx == idx {
				if len(field.Names) > 0 {
					return field.Names[i].Name
				}
				// Unnamed result: we need to name all results in this field list
				// to satisfy Go's "all or none" named return rule.
				f.nameAllResults()
				return field.Names[i].Name
			}
			resultIdx++
		}
	}

	return ""
}

// nameAllResults assigns synthetic names (_aikido_r0, _aikido_r1, ...) to all
// unnamed return values. Go requires that either all or no return values are named,
// so we name them all.
func (f *function) nameAllResults() {
	if f.fn.Type.Results == nil {
		return
	}

	idx := 0
	for _, field := range f.fn.Type.Results.List {
		if len(field.Names) == 0 {
			name := fmt.Sprintf("_aikido_r%d", idx)
			field.Names = []*ast.Ident{ast.NewIdent(name)}
			idx++
		} else {
			idx += len(field.Names)
		}
	}
}
