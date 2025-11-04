package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const toolsFileTemplate = `// This file was created by 'zen-go init', and is used to ensure the
// go.mod file contains the necessary entries for repeatable builds.
//go:build tools

package tools

import (
	// Ensures Aikido Zen instrumentation is present in go.mod
	// Do not remove this unless you want to stop using Aikido.
	_ "github.com/AikidoSec/firewall-go/instrumentation"
	_ "github.com/DataDog/orchestrion" // integration
)
`

func initCommand() error {
	// Parse flags
	force := false
	if len(os.Args) > 2 {
		for _, arg := range os.Args[2:] {
			if arg == "-f" || arg == "--force" {
				force = true
			}
		}
	}

	filename := "orchestrion.tool.go"

	// Check if file already exists
	if !force {
		if _, err := os.Stat(filename); err == nil {
			fmt.Printf("⚠️  %s already exists\n", filename)
			fmt.Println("   Run with --force to overwrite, or delete the file first.")
			return nil
		}
	}

	// Create the file
	// #nosec G306 - 0644 permissions are appropriate for a non-sensitive source file that will be committed to version control
	if err := os.WriteFile(filename, []byte(toolsFileTemplate), 0o644); err != nil {
		return fmt.Errorf("failed to create %s: %w", filename, err)
	}

	absPath, _ := filepath.Abs(filename)
	fmt.Printf("✓ Created %s\n", filename)
	fmt.Printf("  %s\n\n", absPath)
	fmt.Println("Next steps:")
	fmt.Println("  1. Run 'go mod tidy' to update your dependencies")
	fmt.Println("  2. Build with 'orchestrion go build' to enable instrumentation")

	return nil
}
