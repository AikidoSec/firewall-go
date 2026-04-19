package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

const aikidoMainModule = "github.com/AikidoSec/firewall-go"

// FindGoMod walks up from startDir looking for a go.mod file.
// Returns the path if found, or empty string if not found.
func FindGoMod(startDir string) string {
	dir := startDir
	for {
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// CheckModuleVersionSync parses the go.mod at gomodPath and returns an error if
// any github.com/AikidoSec/firewall-go instrumentation submodule is at a different
// version than the main github.com/AikidoSec/firewall-go module.
//
// Returns nil if the main module is not required (not a firewall-go project)
// or if all versions are aligned.
func CheckModuleVersionSync(gomodPath string) error {
	// #nosec G304 - gomodPath is derived from the project source directory
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		return nil
	}

	f, err := modfile.Parse(gomodPath, data, func(_, version string) (string, error) {
		return version, nil
	})
	if err != nil {
		return nil
	}

	var mainVersion string
	for _, req := range f.Require {
		if req.Mod.Path == aikidoMainModule {
			mainVersion = req.Mod.Version
			break
		}
	}

	if mainVersion == "" {
		return nil
	}

	replaced := make(map[string]bool)
	for _, r := range f.Replace {
		replaced[r.Old.Path] = true
	}

	if replaced[aikidoMainModule] {
		return nil
	}

	type mismatch struct{ path, version string }
	var mismatches []mismatch

	for _, req := range f.Require {
		if strings.HasPrefix(req.Mod.Path, aikidoMainModule+"/") && !replaced[req.Mod.Path] && req.Mod.Version != mainVersion {
			mismatches = append(mismatches, mismatch{req.Mod.Path, req.Mod.Version})
		}
	}

	if len(mismatches) == 0 {
		return nil
	}

	var fixes []string
	for _, m := range mismatches {
		fixes = append(fixes, m.path+"@"+mainVersion)
	}

	var details []string
	for _, m := range mismatches {
		details = append(details, fmt.Sprintf("  %s is at %s, expected %s", m.path, m.version, mainVersion))
	}

	return fmt.Errorf(
		"zen-go: instrumentation package version mismatch (%s is at %s):\n%s\nrun: go get %s",
		aikidoMainModule,
		mainVersion,
		strings.Join(details, "\n"),
		strings.Join(fixes, " "),
	)
}
