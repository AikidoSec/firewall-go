package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeInstrumentationHash(t *testing.T) {
	inst, err := NewInstrumentor()
	require.NoError(t, err)

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

func TestComputeInstrumentationHash_DifferentPrependRules(t *testing.T) {
	inst1 := &Instrumentor{
		PrependRules: []PrependRule{
			{ID: "test1", Package: "os", FuncNames: []string{"Open"}},
		},
	}

	inst2 := &Instrumentor{
		PrependRules: []PrependRule{
			{ID: "test2", Package: "os", FuncNames: []string{"Create"}},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1)
	hash2 := ComputeInstrumentationHash(inst2)

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_DifferentInjectDeclRules(t *testing.T) {
	inst1 := &Instrumentor{
		InjectDeclRules: []InjectDeclRule{
			{ID: "test1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst2 := &Instrumentor{
		InjectDeclRules: []InjectDeclRule{
			{ID: "test2", Package: "os", AnchorFunc: "Getuid"},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1)
	hash2 := ComputeInstrumentationHash(inst2)

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_AllRuleTypes(t *testing.T) {
	inst1 := &Instrumentor{
		WrapRules: []WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []PrependRule{
			{ID: "prepend1", Package: "os", FuncNames: []string{"Open"}},
		},
		InjectDeclRules: []InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst2 := &Instrumentor{
		WrapRules: []WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []PrependRule{
			{ID: "prepend2", Package: "os", FuncNames: []string{"Open"}}, // Different ID
		},
		InjectDeclRules: []InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst3 := &Instrumentor{
		WrapRules: []WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []PrependRule{
			{ID: "prepend2", Package: "os", FuncNames: []string{"Open"}},
		},
		InjectDeclRules: []InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getuid"}, // Different anchor
		},
	}

	hash1 := ComputeInstrumentationHash(inst1)
	hash2 := ComputeInstrumentationHash(inst2)
	hash3 := ComputeInstrumentationHash(inst3)

	assert.NotEqual(t, hash1, hash2, "hash should change when prepend rule changes")
	assert.NotEqual(t, hash2, hash3, "hash should change when inject-decl rule changes")
}
