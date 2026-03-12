package hooks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoopRuntime(t *testing.T) {
	n := noopRuntime{}

	assert.NotPanics(t, func() { n.OnOperationCall("op", OperationKindSQL) })
	assert.NotPanics(t, func() { n.OnDomain("example.com", 443) })
	assert.False(t, n.ShouldBlockHostname("example.com"))
}

func TestDefaultRuntimeIsNoop(t *testing.T) {
	original := currentRuntime
	t.Cleanup(func() { currentRuntime = original })

	currentRuntime = noopRuntime{}

	assert.NotPanics(t, func() { OnOperationCall("op", OperationKindSQL) })
	assert.NotPanics(t, func() { OnDomain("example.com", 443) })
	assert.False(t, ShouldBlockHostname("example.com"))
}

func TestPreviousRuntimeRestoredAfterRegister(t *testing.T) {
	original := currentRuntime
	t.Cleanup(func() { currentRuntime = original })

	var callCount int
	currentRuntime = &callCountRuntime{count: &callCount}

	OnOperationCall("inside", OperationKindSQL)
	assert.Equal(t, 1, callCount)

	currentRuntime = original
	OnOperationCall("outside", OperationKindSQL)
	assert.Equal(t, 1, callCount, "call after restore should not reach old runtime")
}

type callCountRuntime struct{ count *int }

func (r *callCountRuntime) OnOperationCall(string, OperationKind) { *r.count++ }
func (r *callCountRuntime) OnDomain(string, uint32)               {}
func (r *callCountRuntime) ShouldBlockHostname(string) bool       { return false }
