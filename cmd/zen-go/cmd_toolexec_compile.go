package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal"
)

func toolexecCompileCommand(stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	// If has -V=full or just -V, then it's a version query
	// Check for -V flag, with optional "full" value
	for _, arg := range toolArgs {
		if arg == "-V=full" || arg == "-V" {
			return toolexecVersionQueryCommand(
				stdout,
				stderr,
				tool, toolArgs,
			)
		}
	}

	var pkgPath, importcfgPath, outputPath string
	for i := range len(toolArgs) {
		if val, ok := extractFlag(toolArgs, i, "-p"); ok {
			pkgPath = val
		} else if val, ok := extractFlag(toolArgs, i, "-importcfg"); ok {
			importcfgPath = val
		} else if val, ok := extractFlag(toolArgs, i, "-o"); ok {
			outputPath = val
		}
	}

	// Get objdir from output path (e.g., /tmp/go-build123/b001/_pkg_.a -> /tmp/go-build123/b001)
	var objdir string
	if outputPath != "" {
		objdir = filepath.Dir(outputPath)
	}

	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: compiling package %s\n", pkgPath)
	}

	// These are the arguments that we want to pass through to the compiler
	// If we modify a file, we need to pass the modified file to the compiler instead of the original file
	newArgs := make([]string, 0, len(toolArgs))
	allAddedImports := make(map[string]string) // import path -> alias

	instrumentor := internal.NewInstrumentor()

	for _, arg := range toolArgs {
		// If doesn't end with .go, it's not a Go file
		// so we can pass it through to the compiler
		if !strings.HasSuffix(arg, ".go") {
			newArgs = append(newArgs, arg)
			continue
		}

		result, modified, addedImports, err := instrumentor.InstrumentFile(arg, pkgPath)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: error instrumenting file %s: %v\n", arg, err)
			newArgs = append(newArgs, arg)
			continue
		}

		if !modified {
			newArgs = append(newArgs, arg)
			continue
		}

		// Track added imports
		for alias, path := range addedImports {
			allAddedImports[alias] = path
		}

		tempFile, err := writeTempFile(arg, result, objdir)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: error writing temp file: %v\n", err)
			newArgs = append(newArgs, arg)
			continue
		}
		newArgs = append(newArgs, tempFile)

		if isDebug() {
			fmt.Fprintf(stderr, "zen-go: transformed %s -> %s\n", arg, tempFile)
			for alias, path := range allAddedImports {
				fmt.Fprintf(stderr, "zen-go: added import %s -> %s\n", alias, path)
			}
		}
	}

	// If we added imports, we need to modify the importcfg
	if len(allAddedImports) > 0 && importcfgPath != "" {
		newImportcfg, err := internal.ExtendImportcfg(importcfgPath, allAddedImports, objdir, stderr, isDebug())
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: warning: failed to extend importcfg: %v\n", err)
		} else if newImportcfg != "" {
			// Replace importcfg in args
			for i := 0; i < len(newArgs); i++ {
				if newArgs[i] == "-importcfg" && i+1 < len(newArgs) {
					newArgs[i+1] = newImportcfg
					if isDebug() {
						fmt.Fprintf(stderr, "zen-go: replaced importcfg with %s\n", newImportcfg)
					}
					break
				}
				if strings.HasPrefix(newArgs[i], "-importcfg=") {
					newArgs[i] = "-importcfg=" + newImportcfg
					if isDebug() {
						fmt.Fprintf(stderr, "zen-go: replaced importcfg with %s\n", newImportcfg)
					}
					break
				}
			}
		}
	}

	// Run the compiler
	err := passthrough(tool, newArgs)
	if err != nil {
		return err
	}

	return nil
}

func extractFlag(args []string, i int, flag string) (string, bool) {
	if args[i] == flag && i+1 < len(args) {
		return args[i+1], true
	}
	if val, ok := strings.CutPrefix(args[i], flag+"="); ok {
		return val, true
	}
	return "", false
}

// passthrough runs the given Golang tool
// For example, it will run the compiler with the arguments originally passed our toolexec command
func passthrough(tool string, args []string) error {
	cmd := exec.Command(tool, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func writeTempFile(origPath string, content []byte, objdir string) (string, error) {
	// Write to objdir/zen-go/src/
	dir := filepath.Join(objdir, "zen-go", "src")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to source directory
		dir = filepath.Dir(origPath)
	}

	base := filepath.Base(origPath)

	// Use predictable name in objdir
	outPath := filepath.Join(dir, base)
	if err := os.WriteFile(outPath, content, 0o644); err != nil {
		return "", err
	}
	return outPath, nil
}
