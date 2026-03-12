package exec

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/shellinjection"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(cmdCtx context.Context, op string, args []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(op, hooks.OperationKindExec)

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

	return vulnerabilities.Scan(ctx, op, shellinjection.ShellInjectionVulnerability, &shellinjection.ScanArgs{
		Command: fullCommand,
	})
}
