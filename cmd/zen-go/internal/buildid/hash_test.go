package buildid

import (
	"testing"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/instrumentor"
	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeInstrumentationHash(t *testing.T) {
	inst, err := instrumentor.NewInstrumentor()
	require.NoError(t, err)

	hash := ComputeInstrumentationHash(inst, "test-version")

	// Hash should be 16 characters (base64 encoded, truncated)
	assert.Len(t, hash, 16)

	// Hash should be consistent
	hash2 := ComputeInstrumentationHash(inst, "test-version")
	assert.Equal(t, hash, hash2)
}

func TestComputeInstrumentationHash_DifferentRules(t *testing.T) {
	inst1 := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "test1", MatchCall: "pkg.Func1"},
		},
	}

	inst2 := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "test2", MatchCall: "pkg.Func2"},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1, "test-version")
	hash2 := ComputeInstrumentationHash(inst2, "test-version")

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_EmptyRules(t *testing.T) {
	inst := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{},
	}

	hash := ComputeInstrumentationHash(inst, "test-version")
	assert.Len(t, hash, 16)
}

func TestComputeInstrumentationHash_DifferentPrependRules(t *testing.T) {
	inst1 := &instrumentor.Instrumentor{
		PrependRules: []rules.PrependRule{
			{ID: "test1", Package: "os", FuncNames: []string{"Open"}},
		},
	}

	inst2 := &instrumentor.Instrumentor{
		PrependRules: []rules.PrependRule{
			{ID: "test2", Package: "os", FuncNames: []string{"Create"}},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1, "test-version")
	hash2 := ComputeInstrumentationHash(inst2, "test-version")

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_DifferentInjectDeclRules(t *testing.T) {
	inst1 := &instrumentor.Instrumentor{
		InjectDeclRules: []rules.InjectDeclRule{
			{ID: "test1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst2 := &instrumentor.Instrumentor{
		InjectDeclRules: []rules.InjectDeclRule{
			{ID: "test2", Package: "os", AnchorFunc: "Getuid"},
		},
	}

	hash1 := ComputeInstrumentationHash(inst1, "test-version")
	hash2 := ComputeInstrumentationHash(inst2, "test-version")

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeInstrumentationHash_AllRuleTypes(t *testing.T) {
	inst1 := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []rules.PrependRule{
			{ID: "prepend1", Package: "os", FuncNames: []string{"Open"}},
		},
		InjectDeclRules: []rules.InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst2 := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []rules.PrependRule{
			{ID: "prepend2", Package: "os", FuncNames: []string{"Open"}}, // Different ID
		},
		InjectDeclRules: []rules.InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getpid"},
		},
	}

	inst3 := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "wrap1", MatchCall: "pkg.Func"},
		},
		PrependRules: []rules.PrependRule{
			{ID: "prepend2", Package: "os", FuncNames: []string{"Open"}},
		},
		InjectDeclRules: []rules.InjectDeclRule{
			{ID: "inject1", Package: "os", AnchorFunc: "Getuid"}, // Different anchor
		},
	}

	hash1 := ComputeInstrumentationHash(inst1, "test-version")
	hash2 := ComputeInstrumentationHash(inst2, "test-version")
	hash3 := ComputeInstrumentationHash(inst3, "test-version")

	assert.NotEqual(t, hash1, hash2, "hash should change when prepend rule changes")
	assert.NotEqual(t, hash2, hash3, "hash should change when inject-decl rule changes")
}

func TestComputeInstrumentationHash_DifferentVersions(t *testing.T) {
	inst := &instrumentor.Instrumentor{
		WrapRules: []rules.WrapRule{
			{ID: "test1", MatchCall: "pkg.Func"},
		},
	}

	hash1 := ComputeInstrumentationHash(inst, "1.0.0")
	hash2 := ComputeInstrumentationHash(inst, "1.0.1")

	assert.NotEqual(t, hash1, hash2, "hash should change when version changes")
}
