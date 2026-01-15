package internal

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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
	Receiver  string            `yaml:"receiver"`  // For prepend rules with receiver: "*pkg.Type"
	Package   string            `yaml:"package"`   // For prepend rules without receiver: target package (e.g., "os")
	Function  string            `yaml:"function"`  // For prepend rules: single "MethodName"
	Functions []string          `yaml:"functions"` // For prepend rules: multiple method names (one-of)
	Imports   map[string]string `yaml:"imports"`
	Template  string            `yaml:"template"`
}

// InstrumentationRules holds all loaded rules
type InstrumentationRules struct {
	WrapRules    []WrapRule
	PrependRules []PrependRule
}

// PrependRule prepends statements to a function body.
// For methods: set ReceiverType (e.g., "*database/sql.DB")
// For standalone functions: set Package (e.g., "os") and leave ReceiverType empty
type PrependRule struct {
	ID           string
	ReceiverType string            // e.g., "*database/sql.DB"
	Package      string            // e.g., "os" (for standalone functions without receiver)
	FuncNames    []string          // e.g., ["Run", "Start"] - matches any of these
	Imports      map[string]string // alias -> import path
	PrependTmpl  string            // template with {{ .Function.Argument N }}
}

// loadRulesFromDir loads all zen.instrument.yml files from a directory tree
func loadRulesFromDir(dir string) (*InstrumentationRules, error) {
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
				ID:        rule.ID,
				MatchCall: rule.Match,
				Imports:   rule.Imports,
				WrapTmpl:  strings.TrimSpace(rule.Template),
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
		}
	}

	return result, nil
}

// findInstrumentationDir finds the instrumentation directory from the firewall-go module
func findInstrumentationDir() string {
	// Use go list to find where the firewall-go module is located
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/AikidoSec/firewall-go")

	// Run from the module root if we can find it
	if modRoot := findModuleRoot(); modRoot != "" {
		cmd.Dir = modRoot
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	modDir := strings.TrimSpace(string(output))
	if modDir == "" {
		return ""
	}

	instDir := filepath.Join(modDir, "instrumentation")
	if info, err := os.Stat(instDir); err == nil && info.IsDir() {
		return instDir
	}

	return ""
}
