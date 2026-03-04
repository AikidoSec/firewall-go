package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/importcfg"
	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/instrumentor"
)

func toolexecCompileCommand(stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	// If has -V=full or just -V, then it's a version query
	if isVersionQuery(toolArgs) {
		return toolexecVersionQueryCommand(
			stdout,
			stderr,
			tool, toolArgs,
		)
	}

	pkgPath, importcfgPath, outputPath := extractCompilerFlags(toolArgs)

	// Get objdir from output path (e.g., /tmp/go-build123/b001/_pkg_.a -> /tmp/go-build123/b001)
	objdir := getObjDir(outputPath)

	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: compiling package %s\n", pkgPath)
	}

	if err := checkZenToolFileIncluded(pkgPath, toolArgs); err != nil {
		return err
	}

	// These are the arguments that we want to pass through to the compiler
	// If we modify a file, we need to pass the modified file to the compiler instead of the original file
	newArgs, allAddedImports, allLinkDeps, err := instrumentFiles(stderr, toolArgs, pkgPath, objdir)
	if err != nil {
		return err
	}

	// If we added imports, we need to modify the importcfg
	if len(allAddedImports) > 0 && importcfgPath != "" {
		newArgs, err = updateImportcfgInArgs(stderr, newArgs, importcfgPath, allAddedImports, objdir)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: warning: failed to update importcfg: %v\n", err)
		}
	}

	// Run the compiler
	err = passthrough(stdout, stderr, tool, newArgs)
	if err != nil {
		return err
	}

	// After successful compile, if we have link-time dependencies, record them
	// in a sidecar file next to the archive. The linker will read these later.
	writeLinkDepsForArchive(stderr, outputPath, allLinkDeps)

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
func passthrough(stdout io.Writer, stderr io.Writer, tool string, args []string) error {
	cmd := exec.Command(tool, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}

func isVersionQuery(args []string) bool {
	for _, arg := range args {
		if arg == "-V=full" || arg == "-V" {
			return true
		}
	}
	return false
}

func extractCompilerFlags(args []string) (pkgPath, importcfgPath, outputPath string) {
	for i := range len(args) {
		if val, ok := extractFlag(args, i, "-p"); ok {
			pkgPath = val
		} else if val, ok := extractFlag(args, i, "-importcfg"); ok {
			importcfgPath = val
		} else if val, ok := extractFlag(args, i, "-o"); ok {
			outputPath = val
		}
	}
	return pkgPath, importcfgPath, outputPath
}

func getObjDir(outputPath string) string {
	if outputPath == "" {
		return ""
	}
	return filepath.Dir(outputPath)
}

func instrumentFiles(stderr io.Writer, toolArgs []string, pkgPath, objdir string) ([]string, map[string]string, []string, error) {
	newArgs := make([]string, 0, len(toolArgs))
	allAddedImports := make(map[string]string) // alias -> import path
	var allAddedLinkDeps []string
	instrumentor, err := instrumentor.NewInstrumentor(version)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, arg := range toolArgs {
		// If doesn't end with .go, it's not a Go file
		// so we can pass it through to the compiler
		if !strings.HasSuffix(arg, ".go") {
			newArgs = append(newArgs, arg)
			continue
		}

		result, err := instrumentor.InstrumentFile(arg, pkgPath)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: error instrumenting file %s: %v\n", arg, err)
			newArgs = append(newArgs, arg)
			continue
		}

		if !result.Modified {
			newArgs = append(newArgs, arg)
			continue
		}

		// Collect added imports (alias -> path), e.g:
		// zengin -> github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin
		maps.Copy(allAddedImports, result.Imports)

		// Collect link dependencies from each file to pass to the linker later
		allAddedLinkDeps = append(allAddedLinkDeps, result.LinkDeps...)

		tempFile, err := writeTempFile(arg, result.Code, objdir)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: error writing temp file: %v\n", err)
			newArgs = append(newArgs, arg)
			continue
		}
		newArgs = append(newArgs, tempFile)

		if isDebug() {
			fmt.Fprintf(stderr, "zen-go: transformed %s -> %s\n", arg, tempFile)
			for alias, path := range result.Imports {
				fmt.Fprintf(stderr, "zen-go: added import %s -> %s\n", alias, path)
			}
			for _, dep := range result.LinkDeps {
				fmt.Fprintf(stderr, "zen-go: added link dep %s\n", dep)
			}
		}
	}

	return newArgs, allAddedImports, allAddedLinkDeps, nil
}

func updateImportcfgInArgs(stderr io.Writer, args []string, importcfgPath string, addedImports map[string]string, objdir string) ([]string, error) {
	newImportcfg, err := importcfg.ExtendImportcfg(importcfgPath, addedImports, objdir, stderr, isDebug())
	if err != nil {
		return args, err
	}

	if newImportcfg == "" {
		return args, nil
	}

	updatedArgs := importcfg.ReplaceImportcfgArg(args, newImportcfg)
	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: replaced importcfg with %s\n", newImportcfg)
	}

	return updatedArgs, nil
}

// checkZenToolFileIncluded checks if the main package is being compiled
// without zen.tool.go. This happens when users run e.g. `go build main.go`
// instead of `go build .`, which causes zen.tool.go to be excluded from the
// build and results in cryptic compiler errors.
func checkZenToolFileIncluded(pkgPath string, toolArgs []string) error {
	if pkgPath != "main" {
		return nil
	}

	var sourceDir string
	hasZenToolFile := false
	for _, arg := range toolArgs {
		if !strings.HasSuffix(arg, ".go") {
			continue
		}
		if sourceDir == "" {
			// The Go compiler processes one package at a time, so all
			// .go files in toolArgs share the same directory.
			sourceDir = filepath.Dir(arg)
		}
		if filepath.Base(arg) == "zen.tool.go" {
			hasZenToolFile = true
			break
		}
	}

	if hasZenToolFile || sourceDir == "" {
		return nil
	}

	zenToolPath := filepath.Join(sourceDir, "zen.tool.go")
	if _, err := os.Stat(zenToolPath); err == nil {
		return errors.New("zen-go: zen.tool.go exists but was not included in the build, use 'go build -toolexec=\"zen-go toolexec\" .' instead of specifying individual files")
	}

	return nil
}

func writeTempFile(origPath string, content []byte, objdir string) (string, error) {
	// Write to objdir/zen-go/src/
	dir := filepath.Join(objdir, "zen-go", "src")
	// #nosec G301 - build artifacts need to be readable by the compiler
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to source directory
		dir = filepath.Dir(origPath)
	}

	base := filepath.Base(origPath)

	// Use predictable name in objdir
	outPath := filepath.Join(dir, base)
	// #nosec G306 -- transformed source files need to be readable by the compiler
	if err := os.WriteFile(outPath, content, 0o644); err != nil {
		return "", err
	}
	return outPath, nil
}
