package hooks

import (
	"testing"

	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/stretchr/testify/assert"
)

func TestNoopRuntime(t *testing.T) {
	n := noopRuntime{}

	assert.NotPanics(t, func() { n.OnOperationCall("op", operation.KindSQL) })
	assert.NotPanics(t, func() { n.OnDomain("example.com", 443) })
	assert.False(t, n.ShouldBlockHostname("example.com"))
}

func TestDefaultRuntimeIsNoop(t *testing.T) {
	original := currentRuntime
	t.Cleanup(func() { currentRuntime = original })

	currentRuntime = noopRuntime{}

	assert.NotPanics(t, func() { OnOperationCall("op", operation.KindSQL) })
	assert.NotPanics(t, func() { OnDomain("example.com", 443) })
	assert.False(t, ShouldBlockHostname("example.com"))
}

func TestPreviousRuntimeRestoredAfterRegister(t *testing.T) {
	original := currentRuntime
	t.Cleanup(func() { currentRuntime = original })

	var callCount int
	currentRuntime = &callCountRuntime{count: &callCount}

	OnOperationCall("inside", operation.KindSQL)
	assert.Equal(t, 1, callCount)

	currentRuntime = original
	OnOperationCall("outside", operation.KindSQL)
	assert.Equal(t, 1, callCount, "call after restore should not reach old runtime")
}

type callCountRuntime struct{ count *int }

func (r *callCountRuntime) OnOperationCall(string, operation.Kind) { *r.count++ }
func (r *callCountRuntime) OnDomain(string, uint32)                {}
func (r *callCountRuntime) ShouldBlockHostname(string) bool        { return false }
