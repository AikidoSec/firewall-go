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
	ID       string            `yaml:"id"`
	Type     string            `yaml:"type"`
	Match    string            `yaml:"match"`
	Imports  map[string]string `yaml:"imports"`
	Template string            `yaml:"template"`
}

// loadRulesFromDir loads all zen.instrument.yml files from a directory tree
func loadRulesFromDir(dir string) ([]WrapRule, error) {
	var wrapRules []WrapRule

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

		wrapRules = append(wrapRules, rules...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return wrapRules, nil
}

// loadRulesFromFile loads rules from a single zen.instrument.yml file
func loadRulesFromFile(path string) ([]WrapRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rulesFile RulesFile
	if err := yaml.Unmarshal(data, &rulesFile); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	var wrapRules []WrapRule
	for _, rule := range rulesFile.Rules {
		if rule.Type != "wrap" {
			continue // Only handle wrap rules for now
		}

		wrapRules = append(wrapRules, WrapRule{
			ID:        rule.ID,
			MatchCall: rule.Match,
			Imports:   rule.Imports,
			WrapTmpl:  strings.TrimSpace(rule.Template),
		})
	}

	return wrapRules, nil
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
