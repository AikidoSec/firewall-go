package hooks

import (
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
)

// Runtime is the interface implemented by the agent and registered at startup.
// Sinks call the package-level functions below rather than importing the agent directly.
type Runtime interface {
	OnOperationCall(op string, kind operation.Kind)
	OnDomain(domain string, port uint32)
	ShouldBlockHostname(hostname string) bool
}

var currentRuntime Runtime = noopRuntime{}

// Register sets the active runtime. Called by the agent during zen.Protect().
func Register(r Runtime) {
	currentRuntime = r
}

func OnOperationCall(op string, kind operation.Kind) {
	currentRuntime.OnOperationCall(op, kind)
}

func OnDomain(domain string, port uint32) {
	currentRuntime.OnDomain(domain, port)
}

func ShouldBlockHostname(hostname string) bool {
	return currentRuntime.ShouldBlockHostname(hostname)
}

type noopRuntime struct{}

func (noopRuntime) OnOperationCall(string, operation.Kind) {}
func (noopRuntime) OnDomain(string, uint32)                {}
func (noopRuntime) ShouldBlockHostname(string) bool        { return false }
