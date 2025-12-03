package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeInstrumentationHash(t *testing.T) {
	inst := NewInstrumentor()
	hash := ComputeInstrumentationHash(inst)

	// Hash should be 16 characters (base64 encoded, truncated)
	assert.Len(t, hash, 16)

	// Hash should be consistent
	hash2 := ComputeInstrumentationHash(inst)
	assert.Equal(t, hash, hash2)
}

func TestComputeInstrumentationHash_DifferentRules(t *testing.T) {
	inst1 := &Instrumentor{
		WrapRules: []WrapRule{
			{ID: "test1", MatchCall: "pkg.Func1"},
		},
	}

	inst2 := &Instrumentor{
		WrapRules: []WrapRule{
			{ID: "test2", MatchCall: "pkg.Func2"},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1)
	hash2 := ComputeInstrumentationHash(inst2)

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_EmptyRules(t *testing.T) {
	inst := &Instrumentor{
		WrapRules: []WrapRule{},
	}

	hash := ComputeInstrumentationHash(inst)
	assert.Len(t, hash, 16)
}
