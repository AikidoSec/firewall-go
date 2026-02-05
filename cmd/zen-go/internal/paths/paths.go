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

// FindInstrumentationDir finds the instrumentation directory from the firewall-go module
func FindInstrumentationDir() string {
	// Use go list to find where the firewall-go module is located
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/AikidoSec/firewall-go")

	// Run from the module root if we can find it
	if modRoot := FindModuleRoot(); modRoot != "" {
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
