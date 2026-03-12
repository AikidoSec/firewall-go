package hooks_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/stretchr/testify/assert"
)

// captureRuntime is a test Runtime that records calls.
type captureRuntime struct {
	operationCalls []struct {
		op   string
		kind hooks.OperationKind
	}
	domainCalls []struct {
		domain string
		port   uint32
	}
	blockHostCalls   []string
	blockHostReturns bool
}

func (r *captureRuntime) OnOperationCall(op string, kind hooks.OperationKind) {
	r.operationCalls = append(r.operationCalls, struct {
		op   string
		kind hooks.OperationKind
	}{op, kind})
}

func (r *captureRuntime) OnDomain(domain string, port uint32) {
	r.domainCalls = append(r.domainCalls, struct {
		domain string
		port   uint32
	}{domain, port})
}

func (r *captureRuntime) ShouldBlockHostname(hostname string) bool {
	r.blockHostCalls = append(r.blockHostCalls, hostname)
	return r.blockHostReturns
}

func TestRegisterReplacesRuntime(t *testing.T) {
	r := &captureRuntime{}
	hooks.Register(r)

	hooks.OnOperationCall("db.query", hooks.OperationKindSQL)

	assert.Len(t, r.operationCalls, 1)
	assert.Equal(t, "db.query", r.operationCalls[0].op)
	assert.Equal(t, hooks.OperationKindSQL, r.operationCalls[0].kind)
}

func TestOnOperationCallDelegates(t *testing.T) {
	r := &captureRuntime{}
	hooks.Register(r)

	hooks.OnOperationCall("exec.Run", hooks.OperationKindExec)
	hooks.OnOperationCall("os.OpenFile", hooks.OperationKindFileSystem)

	assert.Len(t, r.operationCalls, 2)
	assert.Equal(t, hooks.OperationKindExec, r.operationCalls[0].kind)
	assert.Equal(t, hooks.OperationKindFileSystem, r.operationCalls[1].kind)
}

func TestOnDomainDelegates(t *testing.T) {
	r := &captureRuntime{}
	hooks.Register(r)

	hooks.OnDomain("example.com", 443)

	assert.Len(t, r.domainCalls, 1)
	assert.Equal(t, "example.com", r.domainCalls[0].domain)
	assert.Equal(t, uint32(443), r.domainCalls[0].port)
}

func TestShouldBlockHostnameDelegates(t *testing.T) {
	r := &captureRuntime{blockHostReturns: true}
	hooks.Register(r)

	result := hooks.ShouldBlockHostname("evil.com")

	assert.True(t, result)
	assert.Equal(t, []string{"evil.com"}, r.blockHostCalls)
}
