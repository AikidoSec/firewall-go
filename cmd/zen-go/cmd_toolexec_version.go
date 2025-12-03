package main

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal"
)

// toolexecVersionQueryCommand handles the -V=full version query that Go uses to compute build IDs.
// We intercept this and append our instrumentation hash to the version string, which
// ensures that when instrumentation rules change, Go will compute different build IDs
// and rebuild packages.
func toolexecVersionQueryCommand(stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	// Run the actual compiler to get its version string
	cmd := exec.Command(tool, toolArgs...)
	var versionOutput bytes.Buffer
	cmd.Stdout = &versionOutput
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	// Compute hash of instrumentation rules
	inst, err := internal.NewInstrumentor()
	if err != nil {
		return err
	}

	rulesHash := internal.ComputeInstrumentationHash(inst)

	// Append our hash to the version string
	versionStr := strings.TrimSpace(versionOutput.String())
	modifiedVersion := versionStr + ":" + "zen-go@" + rulesHash

	fmt.Fprint(stdout, modifiedVersion)
	if !strings.HasSuffix(modifiedVersion, "\n") {
		fmt.Fprint(stdout, "\n")
	}

	if isDebug() {
		fmt.Fprintf(stderr, "zen-go: version query: %s -> %s\n", versionStr, modifiedVersion)
	}

	return nil
}
