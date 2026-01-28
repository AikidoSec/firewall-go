package exec

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/shellinjection"
)

func Examine(cmdCtx context.Context, op string, args []string) error {
	if config.IsZenDisabled() {
		return nil
	}

	agent.OnOperationCall(op, aikido_types.OperationKindExec)

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
