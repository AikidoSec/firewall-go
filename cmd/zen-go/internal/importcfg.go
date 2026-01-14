package internal

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ExtendImportcfg(origPath string, addedImports map[string]string, objdir string, stderr io.Writer, debug bool) (string, error) {
	content, err := os.ReadFile(origPath)
	if err != nil {
		return "", err
	}

	// Parse existing entries
	existing := make(map[string]bool)
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "packagefile ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "packagefile "), "=", 2)
			if len(parts) == 2 {
				existing[parts[0]] = true
			}
		}
	}

	// Find export paths for added imports
	var newLines []string
	for alias, importPath := range addedImports {
		if debug {
			fmt.Fprintf(stderr, "zen-go: processing import: key=%s value=%s\n", alias, importPath)
		}

		if existing[importPath] {
			continue
		}

		exportPath, err := getPackageExport(importPath)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: warning: could not find export for %s: %v\n", importPath, err)
			continue
		}

		newLines = append(newLines, fmt.Sprintf("packagefile %s=%s", importPath, exportPath))
		existing[importPath] = true

		if debug {
			fmt.Fprintf(stderr, "zen-go: adding to importcfg: %s=%s\n", importPath, exportPath)
		}
	}

	if len(newLines) == 0 {
		if debug {
			fmt.Fprintf(stderr, "zen-go: no new imports to add to importcfg\n")
		}
		return "", nil
	}

	// Write new importcfg
	newContent := strings.TrimSuffix(string(content), "\n") + "\n" + strings.Join(newLines, "\n") + "\n"

	tmpFile, err := createTempFile(objdir)
	if err != nil {
		return "", err
	}

	if _, err := tmpFile.WriteString(newContent); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	tmpFile.Close()

	if debug {
		fmt.Fprintf(stderr, "zen-go: wrote extended importcfg to %s\n", tmpFile.Name())
	}

	return tmpFile.Name(), nil
}

func createTempFile(objdir string) (*os.File, error) {
	if objdir != "" {
		dir := filepath.Join(objdir, "zen-go")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return os.Create(filepath.Join(dir, "importcfg.txt"))
		}
	}
	return os.CreateTemp("", "importcfg_*.txt")
}

func getPackageExport(importPath string) (string, error) {
	// Get the path to ourselves so we can use -toolexec
	// This ensures we get the export path from the same cache as the current build
	selfPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	toolexecArg := selfPath + " toolexec"
	cmd := exec.Command("go", "list", "-toolexec", toolexecArg, "-export", "-f", "{{.Export}}", importPath)
	if modDir := findModuleRoot(); modDir != "" {
		cmd.Dir = modDir
	}

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func findModuleRoot() string {
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
