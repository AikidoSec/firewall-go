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
func NewInstrumentor() (*Instrumentor, error) {
	// Try to load rules from the instrumentation directory
	if instDir := findInstrumentationDir(); instDir != "" {
		rules, err := loadRulesFromDir(instDir)
		if err != nil {
			return nil, err
		}

		return &Instrumentor{WrapRules: rules.WrapRules, PrependRules: rules.PrependRules}, nil
	}

	// No rules found
	return &Instrumentor{}, nil
}

// NewInstrumentorWithRules creates an Instrumentor with the given rules
func NewInstrumentorWithRules(wrapRules []WrapRule, prependRules []PrependRule) *Instrumentor {
	return &Instrumentor{WrapRules: wrapRules, PrependRules: prependRules}
}

type InstrumentFileResult struct {
	Code     []byte
	Modified bool
	Imports  map[string]string
}

func (i *Instrumentor) InstrumentFile(filename string, compilingPkg string) (InstrumentFileResult, error) {
	// Parse the file using go/parser
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return InstrumentFileResult{}, err
	}

	// Build map of existing imports
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := ""

		// The import name refers to the alias
		// If an alias isn't set, then we use the package name
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
		// Matching is based on package.Func
		// e.g. "github.com/gin-gonic/gin.New"
		lastDot := strings.LastIndex(rule.MatchCall, ".")
		if lastDot == -1 {
			continue
		}

		// e.g. "github.com/gin-gonic/gin"
		pkg := rule.MatchCall[:lastDot]

		// e.g. "New"
		funcName := rule.MatchCall[lastDot+1:]

		localPkgName, ok := imports[pkg]
		if !ok {
			continue
		}

		err := transformDeclsWrap(file.Decls, fset, localPkgName, funcName, rule, &modified, importsToAdd)
		if err != nil {
			return InstrumentFileResult{}, err
		}
	}

	// Apply prepend rules
	for _, rule := range i.PrependRules {
		err := transformDeclsPrepend(file.Decls, compilingPkg, rule, &modified, importsToAdd)
		if err != nil {
			return InstrumentFileResult{}, err
		}
	}

	if !modified {
		return InstrumentFileResult{}, nil
	}

	// Add new imports
	err = addImports(file, importsToAdd)
	if err != nil {
		return InstrumentFileResult{}, err
	}

	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, file); err != nil {
		return InstrumentFileResult{}, err
	}

	return InstrumentFileResult{
		Code:     out.Bytes(),
		Modified: true,
		Imports:  importsToAdd,
	}, nil
}
