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
	WrapRules []WrapRule
}

func NewInstrumentor() *Instrumentor {
	return &Instrumentor{
		WrapRules: []WrapRule{
			{
				ID:        "gin.Default",
				MatchCall: "github.com/gin-gonic/gin.Default",
				Imports: map[string]string{
					"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
				},
				WrapTmpl: `func() *gin.Engine { e := {{.}}; e.Use(zengin.GetMiddleware()); return e }()`,
			},
			{
				ID:        "gin.New",
				MatchCall: "github.com/gin-gonic/gin.New",
				Imports: map[string]string{
					"zengin": "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
				},
				WrapTmpl: `func() *gin.Engine { e := {{.}}; e.Use(zengin.GetMiddleware()); return e }()`,
			},
		},
	}
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
