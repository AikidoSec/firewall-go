package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/tui"
)

type instrumentOption struct {
	name        string
	description string
	importPath  string // empty for locked/stdlib items
	locked      bool
}

var (
	sourceOptions = []instrumentOption{
		{name: "gin", description: "Gin web framework", importPath: "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"},
		{name: "chi", description: "Chi router", importPath: "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi.v5"},
		{name: "echo/v4", description: "Echo v4 web framework", importPath: "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v4"},
		{name: "net/http", description: "Standard library (always included)", locked: true},
	}

	sinkOptions = []instrumentOption{
		{name: "pgx", description: "PostgreSQL via pgx/v5", importPath: "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5"},
		{name: "os", description: "File system operations (always included)", locked: true},
		{name: "os/exec", description: "Command execution (always included)", locked: true},
		{name: "path", description: "Path traversal protection (always included)", locked: true},
		{name: "path/filepath", description: "Filepath traversal protection (always included)", locked: true},
		{name: "database/sql", description: "SQL databases (always included)", locked: true},
		{name: "net/http", description: "Outbound HTTP (always included)", locked: true},
	}
)

// availableMap returns a name->importPath map for non-locked options
func availableMap(options []instrumentOption) map[string]string {
	m := make(map[string]string)
	for _, opt := range options {
		if !opt.locked {
			m[opt.name] = opt.importPath
		}
	}
	return m
}

var (
	availableSources = availableMap(sourceOptions)
	availableSinks   = availableMap(sinkOptions)
)

type initConfig struct {
	sources []string
	sinks   []string
}

func generateToolsFile(config initConfig) string {
	var sb strings.Builder

	sb.WriteString(`// This file was created by 'zen-go init', and is used to ensure the
// go.mod file contains the necessary entries for repeatable builds.

package main

import (
	// Ensures Aikido Zen instrumentation is present in go.mod
	// Do not remove this unless you want to stop using Aikido.
	_ "github.com/AikidoSec/firewall-go/instrumentation"
`)

	// Add sources
	if len(config.sources) > 0 {
		sb.WriteString("\n	// Aikido Zen: Sources\n")
		for _, source := range config.sources {
			if pkgPath, ok := availableSources[source]; ok {
				sb.WriteString(fmt.Sprintf("	_ %q\n", pkgPath))
			}
		}
	}

	// Add sinks
	if len(config.sinks) > 0 {
		sb.WriteString("\n	// Aikido Zen: Sinks\n")
		for _, sink := range config.sinks {
			if pkgPath, ok := availableSinks[sink]; ok {
				sb.WriteString(fmt.Sprintf("	_ %q\n", pkgPath))
			}
		}
	}

	sb.WriteString(")\n")

	return sb.String()
}

func parseAndValidateList(flagValue string, available map[string]string, itemType string) ([]string, error) {
	if flagValue == "" {
		return []string{}, nil
	}

	// Split by comma and trim whitespace
	items := strings.Split(flagValue, ",")
	result := make([]string, 0, len(items))
	invalid := []string{}

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if _, ok := available[item]; !ok {
			invalid = append(invalid, item)
		} else {
			result = append(result, item)
		}
	}

	if len(invalid) > 0 {
		availableList := make([]string, 0, len(available))
		for key := range available {
			availableList = append(availableList, key)
		}
		sort.Strings(availableList)

		return nil, fmt.Errorf("invalid %s(s): %s\nAvailable %ss: %s",
			itemType,
			strings.Join(invalid, ", "),
			itemType,
			strings.Join(availableList, ", "),
		)
	}

	return result, nil
}

func initCommand(stdout io.Writer, force bool, sourcesFlag string, sourcesSet bool, sinksFlag string, sinksSet bool) error {
	filename := "zen.tool.go"

	// Check if file already exists
	if !force {
		if _, err := os.Stat(filename); err == nil {
			fmt.Fprintf(stdout, "⚠️  %s already exists\n", filename)
			fmt.Fprintln(stdout, "   Run with --force to overwrite, or delete the file first.")
			return nil
		}
	}

	var selectedSources, selectedSinks []string
	var err error

	// Handle sources: use flag if explicitly set, otherwise prompt
	if sourcesSet {
		selectedSources, err = parseAndValidateList(sourcesFlag, availableSources, "source")
		if err != nil {
			return err
		}
		if len(selectedSources) == 0 && sourcesFlag == "" {
			fmt.Fprintln(stdout, "No sources selected (empty argument provided)")
		}
	} else {
		selectedSources, err = promptForSources()
		if err != nil {
			return fmt.Errorf("source selection cancelled or failed: %w", err)
		}
	}

	// Handle sinks: use flag if explicitly set, otherwise prompt
	if sinksSet {
		selectedSinks, err = parseAndValidateList(sinksFlag, availableSinks, "sink")
		if err != nil {
			return err
		}
		if len(selectedSinks) == 0 && sinksFlag == "" {
			fmt.Fprintln(stdout, "No sinks selected (empty argument provided)")
		}
	} else {
		selectedSinks, err = promptForSinks()
		if err != nil {
			return fmt.Errorf("sink selection cancelled or failed: %w", err)
		}
	}

	// Sort for consistent output
	sort.Strings(selectedSources)
	sort.Strings(selectedSinks)

	config := initConfig{
		sources: selectedSources,
		sinks:   selectedSinks,
	}

	content := generateToolsFile(config)

	// Create the file
	// #nosec G306 - 0644 permissions are appropriate for a non-sensitive source file that will be committed to version control
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to create %s: %w", filename, err)
	}

	absPath, _ := filepath.Abs(filename)
	fmt.Fprintf(stdout, "✓ Created %s\n", filename)
	fmt.Fprintf(stdout, "  %s\n\n", absPath)

	if len(selectedSources) > 0 {
		fmt.Fprintf(stdout, "  Sources: %s\n", strings.Join(selectedSources, ", "))
	}
	if len(selectedSinks) > 0 {
		fmt.Fprintf(stdout, "  Sinks: %s\n", strings.Join(selectedSinks, ", "))
	}

	if len(selectedSources) == 0 && len(selectedSinks) == 0 {
		fmt.Fprintln(stdout, "  No additional instrumentation selected")
	}

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Next steps:")
	fmt.Fprintln(stdout, "  1. Run 'go mod tidy' to update your dependencies")
	fmt.Fprintln(stdout, "  2. Install `zen-go` CLI with 'go install github.com/AikidoSec/firewall-go/cmd/zen-go@latest'")
	fmt.Fprintln(stdout, "  3. Build with 'go build -toolexec=\"zen-go toolexec\"' to enable instrumentation")

	return nil
}

func toSelectItems(options []instrumentOption) []tui.SelectItem {
	items := make([]tui.SelectItem, len(options))
	for i, opt := range options {
		items[i] = tui.SelectItem{
			Name:        opt.name,
			Description: opt.description,
			Locked:      opt.locked,
		}
	}
	return items
}

func promptForSources() ([]string, error) {
	return tui.RunMultiSelect(
		"Sources",
		"Entry points for incoming requests (web frameworks)",
		toSelectItems(sourceOptions),
	)
}

func promptForSinks() ([]string, error) {
	return tui.RunMultiSelect(
		"Sinks",
		"Operations that need protection & monitoring (database, file system, etc.)",
		toSelectItems(sinkOptions),
	)
}
