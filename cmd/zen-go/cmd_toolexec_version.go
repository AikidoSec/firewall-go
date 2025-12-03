package main

import (
	"io"
	"os/exec"
)

func toolexecVersionQueryCommand(stdout io.Writer, stderr io.Writer, tool string, toolArgs []string) error {
	// Run the actual compiler to get its version string
	cmd := exec.Command(tool, toolArgs...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
