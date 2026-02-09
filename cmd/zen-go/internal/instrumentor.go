package internal

import (
	"bytes"
	"go/parser"
	"go/printer"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/paths"
	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
)

type Instrumentor struct {
	WrapRules       []rules.WrapRule
	PrependRules    []rules.PrependRule
	InjectDeclRules []rules.InjectDeclRule
}

// NewInstrumentor creates a new Instrumentor, loading rules from YAML files
func NewInstrumentor() (*Instrumentor, error) {
	dirs := paths.FindInstrumentationDirs()
	if len(dirs) == 0 {
		return &Instrumentor{}, nil
	}

	allRules := &rules.InstrumentationRules{}
	for _, dir := range dirs {
		rulesData, err := rules.LoadRulesFromDir(dir)
		if err != nil {
			return nil, err
		}
		allRules.WrapRules = append(allRules.WrapRules, rulesData.WrapRules...)
		allRules.PrependRules = append(allRules.PrependRules, rulesData.PrependRules...)
		allRules.InjectDeclRules = append(allRules.InjectDeclRules, rulesData.InjectDeclRules...)
	}

	return NewInstrumentorWithRules(allRules), nil
}

// NewInstrumentorWithRules creates an Instrumentor with the given rules
func NewInstrumentorWithRules(rules *rules.InstrumentationRules) *Instrumentor {
	return &Instrumentor{
		WrapRules:       rules.WrapRules,
		PrependRules:    rules.PrependRules,
		InjectDeclRules: rules.InjectDeclRules,
	}
}

type InstrumentFileResult struct {
	Code     []byte
	Modified bool
	Imports  map[string]string // alias -> import path (for compile-time imports)
	LinkDeps []string          // import paths (for link-time dependencies via go:linkname)
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
			// Handle major version suffixes (e.g., /v5 in github.com/go-chi/chi/v5)
			if len(parts) >= 2 && isMajorVersion(name) {
				name = parts[len(parts)-2]
			}
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

		// Skip if the package being compiled is in the exclude list
		if slices.Contains(rule.ExcludePkgs, compilingPkg) {
			continue
		}

		err = transformDeclsWrap(file.Decls, fset, localPkgName, funcName, rule, &modified, importsToAdd)
		if err != nil {
			return InstrumentFileResult{}, err
		}
	}

	// Apply prepend rules (for methods and standalone functions)
	for _, rule := range i.PrependRules {
		err = transformDeclsPrepend(file.Decls, compilingPkg, rule, &modified, importsToAdd)
		if err != nil {
			return InstrumentFileResult{}, err
		}
	}

	// Track links to add (for go:linkname dependencies)
	var linksToAdd []string

	// Apply inject decl rules (for go:linkname declarations)
	for _, rule := range i.InjectDeclRules {
		// Only apply if we're compiling the target package
		if rule.Package != "" && rule.Package != compilingPkg {
			continue
		}

		err = transformDeclsInjectDecl(file, fset, rule, &modified, &linksToAdd)
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
		LinkDeps: linksToAdd,
	}, nil
}

// isMajorVersion checks if s is a Go module major version suffix (e.g., "v2", "v5", "v10")
func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
