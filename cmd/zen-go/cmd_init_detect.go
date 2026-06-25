package main

import (
	"fmt"
	"os"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
	"golang.org/x/mod/modfile"
)

const zenGoModulePath = "github.com/AikidoSec/firewall-go/cmd/zen-go"

func loadProjectGoMod() (map[string]struct{}, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}
	gomodPath := rules.FindGoMod(cwd)
	if gomodPath == "" {
		return nil, fmt.Errorf("go.mod not found in %s or any parent directory", cwd)
	}
	return parseGoModRequires(gomodPath)
}

// parseGoModRequires reads a go.mod file and returns the set of required
// module paths (both direct and indirect). Returns an error if the file
// cannot be read or parsed.
func parseGoModRequires(path string) (map[string]struct{}, error) {
	// #nosec G304 - path is a fixed, well-known filename in the user's project
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	requires := make(map[string]struct{}, len(f.Require))
	for _, r := range f.Require {
		requires[r.Mod.Path] = struct{}{}
	}
	return requires, nil
}

func addZenGoTool() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	gomodPath := rules.FindGoMod(cwd)
	if gomodPath == "" {
		return "", fmt.Errorf("go.mod not found in %s or any parent directory", cwd)
	}

	// #nosec G304 - path is derived from the project source directory
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", gomodPath, err)
	}

	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", gomodPath, err)
	}

	if err = f.AddTool(zenGoModulePath); err != nil {
		return "", fmt.Errorf("add tool to %s: %w", gomodPath, err)
	}

	out, err := f.Format()
	if err != nil {
		return "", fmt.Errorf("format %s: %w", gomodPath, err)
	}

	// #nosec G306 - go.mod is a source file readable by all
	// #nosec G703 - path is derived from the project source directory
	if err := os.WriteFile(gomodPath, out, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", gomodPath, err)
	}

	return gomodPath, nil
}

// detectInstalledOptions returns the names of options whose goModulePath is
// present in requires. Locked items and items without a goModulePath are skipped.
func detectInstalledOptions(options []instrumentOption, requires map[string]struct{}) []string {
	var detected []string
	for _, opt := range options {
		if opt.locked || opt.goModulePath == "" {
			continue
		}
		if _, ok := requires[opt.goModulePath]; ok {
			detected = append(detected, opt.name)
		}
	}
	return detected
}
