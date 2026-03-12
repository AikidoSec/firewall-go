package hooks

// OperationKind identifies the type of operation being tracked.
type OperationKind string

const (
	OperationKindSQL          OperationKind = "sql_op"
	OperationKindNoSQL        OperationKind = "nosql_op"
	OperationKindOutgoingHTTP OperationKind = "outgoing_http_op"
	OperationKindFileSystem   OperationKind = "fs_op"
	OperationKindExec         OperationKind = "exec_op"
	OperationKindDeserialize  OperationKind = "deserialize_op"
	OperationKindAI           OperationKind = "ai_op"
)

// Runtime is the interface implemented by the agent and registered at startup.
// Sinks call the package-level functions below rather than importing the agent directly.
type Runtime interface {
	OnOperationCall(operation string, kind OperationKind)
	OnDomain(domain string, port uint32)
	ShouldBlockHostname(hostname string) bool
}

var currentRuntime Runtime = noopRuntime{}

// Register sets the active runtime. Called by the agent during zen.Protect().
func Register(r Runtime) {
	currentRuntime = r
}

func OnOperationCall(operation string, kind OperationKind) {
	currentRuntime.OnOperationCall(operation, kind)
}

func OnDomain(domain string, port uint32) {
	currentRuntime.OnDomain(domain, port)
}

func ShouldBlockHostname(hostname string) bool {
	return currentRuntime.ShouldBlockHostname(hostname)
}

type noopRuntime struct{}

func (noopRuntime) OnOperationCall(string, OperationKind) {}
func (noopRuntime) OnDomain(string, uint32)               {}
func (noopRuntime) ShouldBlockHostname(string) bool       { return false }
