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
		"chi":     "github.com/AikidoSec/firewall-go/instrumentation/sources/go-chi/chi.v5",
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
	fmt.Fprintln(stdout, "  2. Build with 'go build -toolexec=\"zen-go toolexec\"' to enable instrumentation")

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

func promptForSources() ([]string, error) {
	var selectedSources []string

	sourceOptions := make([]huh.Option[string], 0, len(availableSources))
	for _, source := range getAvailableSources() {
		sourceOptions = append(sourceOptions, huh.NewOption(source, source))
	}

	if len(sourceOptions) == 0 {
		return []string{}, nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select sources to instrument").
				Description("Sources are entry points for requests (web frameworks)").
				Options(sourceOptions...).
				Value(&selectedSources),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return selectedSources, nil
}

func promptForSinks() ([]string, error) {
	var selectedSinks []string

	sinkOptions := make([]huh.Option[string], 0, len(availableSinks))
	for _, sink := range getAvailableSinks() {
		sinkOptions = append(sinkOptions, huh.NewOption(sink, sink))
	}

	if len(sinkOptions) == 0 {
		return []string{}, nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select sinks to instrument").
				Description("Sinks are operations that need protection & monitoring (database, file system, etc.)").
				Options(sinkOptions...).
				Value(&selectedSinks),
		),
	)

	if err := form.Run(); err != nil {
		return nil, err
	}

	return selectedSinks, nil
}
