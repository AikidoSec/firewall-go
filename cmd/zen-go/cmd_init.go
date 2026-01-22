package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
)

// Available sources and sinks
var (
	availableSources = map[string]string{
		"gin":     "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin",
		"chi":     "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi",
		"echo/v4": "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v4",
	}

	availableSinks = map[string]string{
		"pgx": "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx",
	}
)

type initConfig struct {
	sources []string
	sinks   []string
}

func generateToolsFile(config initConfig) string {
	var sb strings.Builder

	sb.WriteString(`// This file was created by 'zen-go init', and is used to ensure the
// go.mod file contains the necessary entries for repeatable builds.
//go:build tools

package tools

import (
	// Ensures Aikido Zen instrumentation is present in go.mod
	// Do not remove this unless you want to stop using Aikido.
	_ "github.com/AikidoSec/firewall-go/instrumentation"
	_ "github.com/DataDog/orchestrion" // integration
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

func initCommand(stdout io.Writer, force bool) error {
	filename := "orchestrion.tool.go"

	// Check if file already exists
	if !force {
		if _, err := os.Stat(filename); err == nil {
			fmt.Fprintf(stdout, "⚠️  %s already exists\n", filename)
			fmt.Fprintln(stdout, "   Run with --force to overwrite, or delete the file first.")
			return nil
		}
	}

	// Show interactive TUI for selection
	selectedSources, selectedSinks, err := promptForSelection()
	if err != nil {
		return fmt.Errorf("selection cancelled or failed: %w", err)
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
	fmt.Fprintln(stdout, "  2. Build with 'orchestrion go build' to enable instrumentation")

	return nil
}

func getAvailableSources() []string {
	sources := make([]string, 0, len(availableSources))
	for source := range availableSources {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources
}

func getAvailableSinks() []string {
	sinks := make([]string, 0, len(availableSinks))
	for sink := range availableSinks {
		sinks = append(sinks, sink)
	}
	sort.Strings(sinks)
	return sinks
}

func promptForSelection() ([]string, []string, error) {
	var selectedSources, selectedSinks []string

	sourceOptions := make([]huh.Option[string], 0, len(availableSources))
	for _, source := range getAvailableSources() {
		sourceOptions = append(sourceOptions, huh.NewOption(source, source))
	}

	sinkOptions := make([]huh.Option[string], 0, len(availableSinks))
	for _, sink := range getAvailableSinks() {
		sinkOptions = append(sinkOptions, huh.NewOption(sink, sink))
	}

	groups := []*huh.Group{}

	if len(sourceOptions) > 0 {
		groups = append(groups, huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select sources to instrument").
				Description("Sources are entry points for requests (web frameworks)").
				Options(sourceOptions...).
				Value(&selectedSources),
		))
	}

	if len(sinkOptions) > 0 {
		groups = append(groups, huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select sinks to instrument").
				Description("Sinks are operations that need protection & monitoring (database, file system, etc.)").
				Options(sinkOptions...).
				Value(&selectedSinks),
		))
	}

	if len(groups) > 0 {
		form := huh.NewForm(groups...)
		if err := form.Run(); err != nil {
			return nil, nil, err
		}
	}

	return selectedSources, selectedSinks, nil
}
