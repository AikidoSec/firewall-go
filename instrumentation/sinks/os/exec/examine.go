package exec

import (
	"context"
	"os"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/shellinjection"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(cmdCtx context.Context, op string, args []string, env []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(op, operation.KindExec)

	ctx := context.Background()
	if cmdCtx != nil {
		ctx = cmdCtx
	}

	if len(args) == 0 {
		return nil
	}

	// Only shell invocations can have injection vulnerabilities
	if !shellinjection.IsShellCommand(args[0]) {
		return nil
	}

	// Extract the command string that will be interpreted by the shell
	commandsToScan := shellinjection.ExtractShellCommandString(args)
	if len(commandsToScan) == 0 {
		return nil
	}

	// We scan everything after the first '-c' to ensure we cover all potential cases
	// such as, unlikely scenarios like:
	//   cmd := exec.Command("sh", "-c", "$0", userInput)
	fullCommand := strings.Join(commandsToScan, " ")

	// Expand environment variables in the command string to detect injection
	// through Cmd.Env. When a shell command like "sh -c $PAYLOAD" is executed
	// with PAYLOAD set in Cmd.Env, the shell expands the variable before execution.
	// We need to expand it here too so we can scan the actual command that will run.
	expandedCommand := ExpandEnvInCommand(fullCommand, env)

	return vulnerabilities.ScanWithOptions(ctx, op, shellinjection.ShellInjectionVulnerability, &shellinjection.ScanArgs{
		Command: expandedCommand,
	}, vulnerabilities.ScanOptions{Module: "os/exec"})
}

// ExpandEnvInCommand expands environment variables in the command string using
// the provided environment. This handles both $VAR and ${VAR} syntax.
// If env is nil or empty, it uses the process environment as a fallback.
func ExpandEnvInCommand(command string, env []string) string {
	// Build a map of environment variables for quick lookup
	envMap := make(map[string]string)
	
	// Add custom environment variables from Cmd.Env
	for _, e := range env {
		if idx := strings.IndexByte(e, '='); idx > 0 {
			key := e[:idx]
			value := e[idx+1:]
			envMap[key] = value
		}
	}
	
	// Expand variables in the command string
	// Use os.Expand which handles both $VAR and ${VAR} syntax
	expanded := os.Expand(command, func(key string) string {
		// First check custom environment
		if val, ok := envMap[key]; ok {
			return val
		}
		// Fall back to process environment
		return os.Getenv(key)
	})
	
	return expanded
}
