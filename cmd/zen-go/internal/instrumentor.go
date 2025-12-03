package internal

import (
	"bytes"
	"go/parser"
	"go/printer"
	"go/token"
	"strconv"
	"strings"
)

// WrapRule wraps a function call expression
type WrapRule struct {
	ID        string
	MatchCall string
	Imports   map[string]string
	WrapTmpl  string
}

type Instrumentor struct {
	WrapRules    []WrapRule
	PrependRules []PrependRule
}

// NewInstrumentor creates a new Instrumentor, loading rules from YAML files
func NewInstrumentor() *Instrumentor {
	// Try to load rules from the instrumentation directory
	if instDir := FindInstrumentationDir(); instDir != "" {
		if rules, err := LoadRulesFromDir(instDir); err == nil {
			return &Instrumentor{
				WrapRules:    rules.WrapRules,
				PrependRules: rules.PrependRules,
			}
		}
	}

	// No rules found
	return &Instrumentor{}
}

// NewInstrumentorWithRules creates an Instrumentor with the given wrap rules (useful for testing)
func NewInstrumentorWithRules(rules []WrapRule) *Instrumentor {
	return &Instrumentor{WrapRules: rules}
}

// NewInstrumentorWithAllRules creates an Instrumentor with all rule types (useful for testing)
func NewInstrumentorWithAllRules(wrapRules []WrapRule, prependRules []PrependRule) *Instrumentor {
	return &Instrumentor{WrapRules: wrapRules, PrependRules: prependRules}
}

func (i *Instrumentor) InstrumentFile(filename string, compilingPkg string) ([]byte, bool, map[string]string, error) {
	// Parse the file using go/parser
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return nil, false, nil, err
	}

	// Build map of existing imports
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := ""
		if imp.Name != nil {
			name = imp.Name.String()
		} else {
			parts := strings.Split(path, "/")
			name = parts[len(parts)-1]
		}
		imports[path] = name
	}

	modified := false
	importsToAdd := make(map[string]string)

	// Apply wrap rules
	for _, rule := range i.WrapRules {
		lastDot := strings.LastIndex(rule.MatchCall, ".")
		if lastDot == -1 {
			continue
		}
		pkg := rule.MatchCall[:lastDot]
		funcName := rule.MatchCall[lastDot+1:]

		localPkgName, ok := imports[pkg]
		if !ok {
			continue
		}

		transformDeclsWrap(file.Decls, fset, localPkgName, funcName, rule, &modified, importsToAdd)
	}

	// Apply prepend rules
	for _, rule := range i.PrependRules {
		transformDeclsPrepend(file.Decls, compilingPkg, rule, &modified, importsToAdd)
	}

	if !modified {
		return nil, false, nil, nil
	}

	// Add new imports
	addImports(file, importsToAdd)

	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, file); err != nil {
		return nil, false, nil, err
	}

	return out.Bytes(), true, importsToAdd, nil
}
