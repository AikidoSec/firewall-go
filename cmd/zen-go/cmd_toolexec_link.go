package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/importcfg"
	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/linkdeps"
)

// toolexecLinkCommand is invoked by Go's -toolexec flag when linking.
// Example args:
//
//	tool: "/usr/local/go/pkg/tool/darwin_arm64/link"
//	toolArgs: ["-o", "/path/to/output", "-importcfg", "/tmp/importcfg", "-buildmode=exe", "main.a"]
//
// zenGoBuildFlag is the -X linker flag that marks the binary as compiled with zen-go.
// zen.Protect() checks this at runtime to warn if the binary was not compiled with zen-go.
const zenGoBuildFlag = "github.com/AikidoSec/firewall-go/internal/agent/config.compiledWithZenGo=true"

func toolexecLinkCommand(stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	importcfgPath := extractLinkerImportcfg(toolArgs)
	if importcfgPath == "" {
		return passthrough(stdout, stderr, tool, toolArgs)
	}

	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: intercepting linker\n")
	}

	args := make([]string, len(toolArgs))
	copy(args, toolArgs)

	// Read the importcfg to find all archives
	// #nosec G304 - importcfgPath comes from Go toolchain args, not user input
	content, err := os.ReadFile(importcfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "zen-go: warning: failed to read importcfg: %v\n", err)
	} else {
		// Collect all link deps from all archives
		allLinkDeps := collectLinkDeps(content, stderr)
		if len(allLinkDeps) > 0 {
			// Find deps we introduced that aren't in the original importcfg.
			// Example: if we injected a go:linkname pointing to
			// github.com/AikidoSec/firewall-go/instrumentation/sinks/os,
			// that package won't be in the importcfg unless the app already used it.
			newLines := resolveMissingDeps(content, allLinkDeps, stderr)
			if len(newLines) > 0 {
				newImportcfgPath, err := writeExtendedLinkerImportcfg(content, newLines)
				if err != nil {
					fmt.Fprintf(stderr, "zen-go: warning: failed to write extended importcfg: %v\n", err)
				} else {
					defer func() { _ = os.Remove(newImportcfgPath) }()
					args = importcfg.ReplaceImportcfgArg(args, newImportcfgPath)
				}
			}
		}
	}

	// Inject build marker so zen.Protect() can detect zen-go compilation
	args = insertLinkerFlags(args, "-X", zenGoBuildFlag)

	return passthrough(stdout, stderr, tool, args)
}

func extractLinkerImportcfg(args []string) string {
	for i := range len(args) {
		if val, ok := extractFlag(args, i, "-importcfg"); ok {
			return val
		}
	}
	return ""
}

func collectLinkDeps(importcfgContent []byte, stderr io.Writer) map[string]bool {
	allLinkDeps := make(map[string]bool)
	lines := strings.Split(string(importcfgContent), "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "packagefile ") {
			continue
		}

		parts := strings.SplitN(strings.TrimPrefix(line, "packagefile "), "=", 2)
		if len(parts) != 2 {
			continue
		}

		archivePath := parts[1]
		deps, err := linkdeps.ReadLinkDeps(archivePath)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: warning: could not read linkdeps: %v\n", err)
			continue
		}

		if len(deps) > 0 {
			for _, dep := range deps {
				allLinkDeps[dep] = true
			}
			if isDebug() {
				fmt.Fprintf(stderr, "zen-go: found link deps in %s: %v\n", parts[0], deps)
			}
		}
	}

	return allLinkDeps
}

func resolveMissingDeps(importcfgContent []byte, allLinkDeps map[string]bool, stderr io.Writer) []string {
	// Parse existing packages in importcfg
	existing := make(map[string]bool)
	lines := strings.Split(string(importcfgContent), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "packagefile ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "packagefile "), "=", 2)
			if len(parts) == 2 {
				existing[parts[0]] = true
			}
		}
	}

	// Find missing deps and resolve their export paths
	var newLines []string
	for dep := range allLinkDeps {
		if existing[dep] {
			if isDebug() {
				fmt.Fprintf(stderr, "zen-go: link dep %s already in importcfg\n", dep)
			}
			continue
		}

		exportPath, err := importcfg.GetPackageExport(dep)
		if err != nil {
			fmt.Fprintf(stderr, "zen-go: warning: could not find export for link dep %s: %v\n", dep, err)
			continue
		}

		newLines = append(newLines, fmt.Sprintf("packagefile %s=%s", dep, exportPath))
		if isDebug() {
			fmt.Fprintf(stderr, "zen-go: adding link dep to importcfg: %s=%s\n", dep, exportPath)
		}
	}

	return newLines
}

func writeExtendedLinkerImportcfg(originalContent []byte, newLines []string) (string, error) {
	newContent := string(originalContent)
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += strings.Join(newLines, "\n") + "\n"

	tmpFile, err := os.CreateTemp("", "importcfg_link_*.txt")
	if err != nil {
		return "", err
	}

	if _, err := tmpFile.WriteString(newContent); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	_ = tmpFile.Close()

	if isDebug() {
		fmt.Fprintf(os.Stderr, "zen-go: wrote extended linker importcfg to %s\n", tmpFile.Name())
	}

	return tmpFile.Name(), nil
}


// insertLinkerFlags inserts flags before the last argument (the archive file),
// since the Go linker expects flags before positional arguments.
func insertLinkerFlags(args []string, flags ...string) []string {
	if len(args) == 0 {
		return flags
	}
	result := make([]string, 0, len(args)+len(flags))
	result = append(result, args[:len(args)-1]...)
	result = append(result, flags...)
	result = append(result, args[len(args)-1])
	return result
}

// writeLinkDepsForArchive writes link dependencies for the compiled archive if any exist.
func writeLinkDepsForArchive(stderr io.Writer, outputPath string, linkDeps []string) {
	if len(linkDeps) == 0 {
		return
	}

	if outputPath == "" {
		return
	}

	// Only write if the output file exists (it should after successful compilation)
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		return
	}

	if err := linkdeps.WriteLinkDeps(outputPath, linkDeps, stderr, isDebug()); err != nil {
		fmt.Fprintf(stderr, "zen-go: warning: failed to write link deps: %v\n", err)
	}
}
