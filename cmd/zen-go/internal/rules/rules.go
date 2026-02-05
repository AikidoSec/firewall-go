package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RulesFile represents the structure of a zen.instrument.yml file
type RulesFile struct {
	Meta  RulesMeta `yaml:"meta"`
	Rules []Rule    `yaml:"rules"`
}

// RulesMeta contains metadata about the rules file
type RulesMeta struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Rule represents a single instrumentation rule
type Rule struct {
	ID        string            `yaml:"id"`
	Type      string            `yaml:"type"`
	Match     string            `yaml:"match"`     // For wrap rules: "pkg.Func"
	Exclude   []string          `yaml:"exclude"`   // For wrap rules: packages to exclude from instrumentation
	Receiver  string            `yaml:"receiver"`  // For prepend rules with receiver: "*pkg.Type"
	Package   string            `yaml:"package"`   // For prepend/inject-decl rules: target package (e.g., "os")
	Function  string            `yaml:"function"`  // For prepend rules: single "MethodName"
	Functions []string          `yaml:"functions"` // For prepend rules: multiple method names (one-of)
	Anchor    string            `yaml:"anchor"`    // For inject-decl rules: anchor function name
	Links     []string          `yaml:"links"`     // For inject-decl rules: packages to link
	Imports   map[string]string `yaml:"imports"`
	Template  string            `yaml:"template"`
}

// InstrumentationRules holds all loaded rules
type InstrumentationRules struct {
	WrapRules       []WrapRule
	PrependRules    []PrependRule
	InjectDeclRules []InjectDeclRule
}

// WrapRule wraps a function call expression
type WrapRule struct {
	ID          string
	MatchCall   string
	ExcludePkgs []string // Packages to exclude from this rule
	Imports     map[string]string
	WrapTmpl    string
}

// PrependRule prepends statements to a function body.
// For methods: set ReceiverType (e.g., "*database/sql.DB")
// For standalone functions: set Package (e.g., "os") and leave ReceiverType empty
type PrependRule struct {
	ID           string
	ReceiverType string            // e.g., "*database/sql.DB" (for methods)
	Package      string            // e.g., "os" (for standalone functions without receiver)
	FuncNames    []string          // e.g., ["Run", "Start"] - matches any of these
	Imports      map[string]string // alias -> import path
	PrependTmpl  string            // template with {{ .Function.Argument N }}
}

// InjectDeclRule injects declarations into a package (e.g., go:linkname)
type InjectDeclRule struct {
	ID           string
	Package      string   // Package being compiled, e.g., "os"
	AnchorFunc   string   // Function to attach declaration to (e.g., "Getpid")
	Links        []string // Packages needed for linking
	DeclTemplate string   // The declaration to inject
}

// LoadRulesFromDir loads all zen.instrument.yml files from a directory tree
func LoadRulesFromDir(dir string) (*InstrumentationRules, error) {
	result := &InstrumentationRules{}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(d.Name(), "zen.instrument.yml") {
			return nil
		}

		rules, err := loadRulesFromFile(path)
		if err != nil {
			return fmt.Errorf("loading %s: %w", path, err)
		}

		result.WrapRules = append(result.WrapRules, rules.WrapRules...)
		result.PrependRules = append(result.PrependRules, rules.PrependRules...)
		result.InjectDeclRules = append(result.InjectDeclRules, rules.InjectDeclRules...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// loadRulesFromFile loads rules from a single zen.instrument.yml file
func loadRulesFromFile(path string) (*InstrumentationRules, error) {
	// #nosec G304 - path is from project's instrumentation directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rulesFile RulesFile
	if err := yaml.Unmarshal(data, &rulesFile); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	result := &InstrumentationRules{}

	for _, rule := range rulesFile.Rules {
		switch rule.Type {
		case "wrap":
			result.WrapRules = append(result.WrapRules, WrapRule{
				ID:          rule.ID,
				MatchCall:   rule.Match,
				ExcludePkgs: rule.Exclude,
				Imports:     rule.Imports,
				WrapTmpl:    strings.TrimSpace(rule.Template),
			})
		case "prepend":
			// Support both "function" (single) and "functions" (multiple)
			funcNames := rule.Functions
			if len(funcNames) == 0 && rule.Function != "" {
				funcNames = []string{rule.Function}
			}
			result.PrependRules = append(result.PrependRules, PrependRule{
				ID:           rule.ID,
				ReceiverType: rule.Receiver,
				Package:      rule.Package,
				FuncNames:    funcNames,
				Imports:      rule.Imports,
				PrependTmpl:  strings.TrimSpace(rule.Template),
			})
		case "inject-decl":
			result.InjectDeclRules = append(result.InjectDeclRules, InjectDeclRule{
				ID:           rule.ID,
				Package:      rule.Package,
				AnchorFunc:   rule.Anchor,
				Links:        rule.Links,
				DeclTemplate: strings.TrimSpace(rule.Template),
			})
		}
	}

	return result, nil
}
