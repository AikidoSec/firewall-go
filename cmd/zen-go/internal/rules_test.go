package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRulesFromFile_WrapRule(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: test-package
  description: Test rules

rules:
  - id: test.Func
    type: wrap
    match: github.com/example/pkg.Func
    imports:
      mypkg: github.com/example/mypkg
    template: |
      wrap({{.}})
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	require.Len(t, rules.WrapRules, 1)
	require.Empty(t, rules.PrependRules)

	assert.Equal(t, "test.Func", rules.WrapRules[0].ID)
	assert.Equal(t, "github.com/example/pkg.Func", rules.WrapRules[0].MatchCall)
	assert.Equal(t, map[string]string{"mypkg": "github.com/example/mypkg"}, rules.WrapRules[0].Imports)
	assert.Equal(t, "wrap({{.}})", rules.WrapRules[0].WrapTmpl)
}

func TestLoadRulesFromFile_PrependRule(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: test-package

rules:
  - id: sql.DB.QueryContext
    type: prepend
    receiver: "*database/sql.DB"
    function: QueryContext
    imports:
      sink: github.com/example/sink
    template: |
      if err := sink.Check({{ .Function.Argument 0 }}); err != nil {
        return nil, err
      }
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	require.Empty(t, rules.WrapRules)
	require.Len(t, rules.PrependRules, 1)

	assert.Equal(t, "sql.DB.QueryContext", rules.PrependRules[0].ID)
	assert.Equal(t, "*database/sql.DB", rules.PrependRules[0].ReceiverType)
	assert.Equal(t, "QueryContext", rules.PrependRules[0].FuncName)
	assert.Equal(t, map[string]string{"sink": "github.com/example/sink"}, rules.PrependRules[0].Imports)
}

func TestLoadRulesFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested directory structure
	subDir := filepath.Join(tmpDir, "sources", "example")
	err := os.MkdirAll(subDir, 0o755)
	require.NoError(t, err)

	// Create a YAML file in the subdirectory
	yamlPath := filepath.Join(subDir, "zen.instrument.yml")
	yamlContent := `
meta:
  name: example
  description: Example rules

rules:
  - id: example.New
    type: wrap
    match: github.com/example/pkg.New
    imports:
      exwrap: github.com/example/wrapper
    template: |
      exwrap.Wrap({{.}})
`
	err = os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromDir(tmpDir)
	require.NoError(t, err)
	require.Len(t, rules.WrapRules, 1)

	assert.Equal(t, "example.New", rules.WrapRules[0].ID)
	assert.Equal(t, "github.com/example/pkg.New", rules.WrapRules[0].MatchCall)
}

func TestLoadRulesFromDir_MultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two subdirectories with YAML files
	for _, name := range []string{"pkg1", "pkg2"} {
		subDir := filepath.Join(tmpDir, name)
		err := os.MkdirAll(subDir, 0o755)
		require.NoError(t, err)

		yamlPath := filepath.Join(subDir, "zen.instrument.yml")
		yamlContent := `
meta:
  name: ` + name + `
rules:
  - id: ` + name + `.Func
    type: wrap
    match: github.com/` + name + `.Func
    imports:
      wrap: github.com/wrapper
    template: wrap({{.}})
`
		err = os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
		require.NoError(t, err)
	}

	rules, err := loadRulesFromDir(tmpDir)
	require.NoError(t, err)
	require.Len(t, rules.WrapRules, 2)
}

func TestLoadRulesFromFile_MixedRules(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: mixed-rules
rules:
  - id: wrap-rule
    type: wrap
    match: pkg.Func
    imports: {}
    template: wrap({{.}})
  - id: prepend-rule
    type: prepend
    receiver: "*pkg.Type"
    function: Method
    imports: {}
    template: before()
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	require.Len(t, rules.WrapRules, 1)
	require.Len(t, rules.PrependRules, 1)
	assert.Equal(t, "wrap-rule", rules.WrapRules[0].ID)
	assert.Equal(t, "prepend-rule", rules.PrependRules[0].ID)
}

func TestLoadRulesFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	err := os.WriteFile(yamlPath, []byte("not: valid: yaml: content"), 0o600)
	require.NoError(t, err)

	_, err = loadRulesFromFile(yamlPath)
	assert.Error(t, err)
}

func TestLoadRulesFromDir_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	rules, err := loadRulesFromDir(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, rules.WrapRules)
	assert.Empty(t, rules.PrependRules)
}
