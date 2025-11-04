package exec

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/shellinjection"
)

func Examine(cmdCtx context.Context, args []string, op string) error {
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

	return vulnerabilities.Scan(ctx, op, shellinjection.ShellInjectionVulnerability, &shellinjection.ScanArgs{
		Command: commandsToScan[0],
	})
}
