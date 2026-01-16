package internal

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const linkdepsExtension = ".zenlinkdeps"

// WriteLinkDeps writes link-time dependencies to a sidecar file next to the archive.
// These dependencies are packages that need to be linked into the final binary
// but are not direct imports of the package being compiled.
func WriteLinkDeps(archivePath string, deps []string, stderr io.Writer, debug bool) error {
	depsFile := archivePath + linkdepsExtension
	content := strings.Join(deps, "\n")
	// #nosec G306 -- link deps file needs to be readable by the linker
	if err := os.WriteFile(depsFile, []byte(content), 0o644); err != nil {
		return err
	}

	if debug {
		fmt.Fprintf(stderr, "zen-go: wrote link deps to %s: %v\n", depsFile, deps)
	}

	return nil
}

// ReadLinkDeps reads link-time dependencies from a sidecar file next to the archive.
// Returns nil if the file doesn't exist (which is not an error - it means no link deps).
func ReadLinkDeps(archivePath string) ([]string, error) {
	depsFile := archivePath + linkdepsExtension
	// #nosec G304 - depsFile is derived from archivePath which comes from Go toolchain
	content, err := os.ReadFile(depsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var deps []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			deps = append(deps, line)
		}
	}
	return deps, nil
}
