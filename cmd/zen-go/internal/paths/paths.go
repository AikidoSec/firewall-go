package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindModuleRoot finds the root directory of the current Go module
func FindModuleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// FindInstrumentationDirs finds all directories containing instrumentation rules.
// This includes the root module's instrumentation/ directory as well as any
// separately-versioned instrumentation submodules (e.g., gin, echo, pgx).
func FindInstrumentationDirs() []string {
	modRoot := FindModuleRoot()
	rootModuleDir := findModuleDir(modRoot, "github.com/AikidoSec/firewall-go")
	submoduleDirs := findSubmoduleDirs(modRoot)
	return collectInstrumentationDirs(rootModuleDir, submoduleDirs)
}

// collectInstrumentationDirs builds the list of directories to scan for rules.
// It appends /instrumentation to the root module dir, then adds any submodule dirs.
// Duplicates are avoided at the loading level: LoadRulesFromDir skips subdirectories
// that contain their own go.mod (i.e., separate modules discovered via submoduleDirs).
func collectInstrumentationDirs(rootModuleDir string, submoduleDirs []string) []string {
	var dirs []string

	if rootModuleDir != "" {
		instDir := filepath.Join(rootModuleDir, "instrumentation")
		if info, err := os.Stat(instDir); err == nil && info.IsDir() {
			dirs = append(dirs, instDir)
		}
	}

	dirs = append(dirs, submoduleDirs...)

	return dirs
}

// findModuleDir returns the directory for a specific Go module.
func findModuleDir(modRoot string, modulePath string) string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePath)
	if modRoot != "" {
		cmd.Dir = modRoot
	}

	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	dir := strings.TrimSpace(string(output))
	if dir == "" {
		return ""
	}
	return dir
}

// findSubmoduleDirs returns directories for all firewall-go instrumentation submodules
// that the current project depends on.
func findSubmoduleDirs(modRoot string) []string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/AikidoSec/firewall-go/instrumentation/...")
	if modRoot != "" {
		cmd.Dir = modRoot
	}

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var dirs []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			dirs = append(dirs, line)
		}
	}
	return dirs
}
