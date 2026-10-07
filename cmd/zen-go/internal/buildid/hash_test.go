package buildid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/instrumentor"
	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRules = `meta:
  name: cache-test
rules:
  - id: runtime.context
    type: add-field
    package: runtime
    struct: g
    fields:
      - name: context
        type: interface{}
  - id: runtime.helpers
    type: add-file
    package: runtime
    file: helpers.go
`

// Load through the real loader and instrumentor constructor to exercise propagation
// of the raw YAML bytes, rather than constructing only the hash inputs by hand.
func loadTestInstrumentor(t *testing.T, dir string) *instrumentor.Instrumentor {
	t.Helper()
	r, err := rules.LoadRulesFromDir(dir)
	require.NoError(t, err)
	inst, err := instrumentor.NewInstrumentorWithRules(r, "999.0.0")
	require.NoError(t, err)
	return inst
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestComputeInstrumentationHash(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "zen.instrument.yml"), testRules)
	writeTestFile(t, filepath.Join(dir, "helpers.go"), "package runtime\nfunc helper() {}\n")
	inst := loadTestInstrumentor(t, dir)
	hash := ComputeInstrumentationHash(inst, "1.0.0")
	assert.Len(t, hash, 16)
	assert.Equal(t, hash, ComputeInstrumentationHash(inst, "1.0.0"))
	assert.NotEqual(t, hash, ComputeInstrumentationHash(inst, "1.0.1"))
}

func TestComputeInstrumentationHash_RawRules(t *testing.T) {
	for _, tc := range []struct {
		name, content string
	}{
		{"add-field", strings.Replace(testRules, "name: context", "name: new_context", 1)},
		{"add-file imports", testRules + "    imports:\n      helper: example.com/helper\n"},
		{"comments", "# comment-only edit\n" + testRules},
		{"future fields", testRules + "    future-field: value\n"},
		{"wrap excludes", testRules + "  - id: wrap\n    type: wrap\n    match: pkg.Func\n    exclude: [example.com/excluded]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "zen.instrument.yml")
			writeTestFile(t, path, testRules)
			before := ComputeInstrumentationHash(loadTestInstrumentor(t, dir), "v")
			writeTestFile(t, path, tc.content)
			after := ComputeInstrumentationHash(loadTestInstrumentor(t, dir), "v")
			assert.NotEqual(t, before, after)
		})
	}
}

func TestComputeInstrumentationHash_AddFileContents(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "zen.instrument.yml"), testRules)
	path := filepath.Join(dir, "helpers.go")
	writeTestFile(t, path, "package runtime\nfunc helper() int { return 1 }\n")
	inst := loadTestInstrumentor(t, dir)
	before := ComputeInstrumentationHash(inst, "v")
	writeTestFile(t, path, "package runtime\nfunc helper() int { return 2 }\n")
	assert.NotEqual(t, before, ComputeInstrumentationHash(inst, "v"))
}

func TestComputeInstrumentationHash_MachineIndependent(t *testing.T) {
	var hashes []string
	for range 2 {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "zen.instrument.yml"), testRules)
		writeTestFile(t, filepath.Join(dir, "helpers.go"), "package runtime\n")
		hashes = append(hashes, ComputeInstrumentationHash(loadTestInstrumentor(t, dir), "v"))
	}
	assert.Equal(t, hashes[0], hashes[1])
}

func TestComputeInstrumentationHash_UnreadableAddFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "zen.instrument.yml"), testRules)
	inst := loadTestInstrumentor(t, dir)
	missing := ComputeInstrumentationHash(inst, "v")
	assert.Len(t, missing, 16)
	path := filepath.Join(dir, "helpers.go")
	writeTestFile(t, path, "")
	assert.NotEqual(t, missing, ComputeInstrumentationHash(inst, "v"), "empty and unreadable differ")
	require.NoError(t, os.Remove(path))
	assert.Equal(t, missing, ComputeInstrumentationHash(inst, "v"))
}

func TestComputeInstrumentationHash_LoadingOrder(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.zen.instrument.yml")
	second := filepath.Join(dir, "b.zen.instrument.yml")
	writeTestFile(t, first, "rules: []\n# first\n")
	writeTestFile(t, second, "rules: []\n# second\n")
	before := ComputeInstrumentationHash(loadTestInstrumentor(t, dir), "v")
	writeTestFile(t, first, "rules: []\n# second\n")
	writeTestFile(t, second, "rules: []\n# first\n")
	assert.NotEqual(t, before, ComputeInstrumentationHash(loadTestInstrumentor(t, dir), "v"))
}

func TestComputeInstrumentationHash_EmptyRules(t *testing.T) {
	assert.Len(t, ComputeInstrumentationHash(&instrumentor.Instrumentor{}, "v"), 16)
}
