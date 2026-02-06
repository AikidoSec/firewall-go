package rules

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
	assert.Equal(t, []string{"QueryContext"}, rules.PrependRules[0].FuncNames)
	assert.Equal(t, map[string]string{"sink": "github.com/example/sink"}, rules.PrependRules[0].Imports)
}

func TestLoadRulesFromFile_PrependRuleMultipleFuncs(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: test-package
rules:
  - id: sql.DB.QueryContext
    type: prepend
    receiver: "*database/sql.DB"
    functions:
      - QueryContext
      - ExecContext
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
	assert.Equal(t, []string{"QueryContext", "ExecContext"}, rules.PrependRules[0].FuncNames)
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

	rules, err := LoadRulesFromDir(tmpDir)
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

	rules, err := LoadRulesFromDir(tmpDir)
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

	rules, err := LoadRulesFromDir(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, rules.WrapRules)
	assert.Empty(t, rules.PrependRules)
}

func TestLoadRulesFromFile_PrependRuleWithPackage(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: os
  description: OS instrumentation

rules:
  - id: os.OpenFile
    type: prepend
    package: os
    function: OpenFile
    imports:
      sink: github.com/example/sink
    template: |
      if err := sink.Check({{ .Function.Argument 0 }}); err != nil { return nil, err }
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	require.Len(t, rules.PrependRules, 1)

	assert.Equal(t, "os.OpenFile", rules.PrependRules[0].ID)
	assert.Equal(t, "os", rules.PrependRules[0].Package)
	assert.Equal(t, []string{"OpenFile"}, rules.PrependRules[0].FuncNames)
	assert.Empty(t, rules.PrependRules[0].ReceiverType)
	assert.Equal(t, map[string]string{"sink": "github.com/example/sink"}, rules.PrependRules[0].Imports)
}

func TestLoadRulesFromFile_InjectDeclRule(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: os
  description: OS instrumentation

rules:
  - id: os.linkname
    type: inject-decl
    package: os
    anchor: Getpid
    links:
      - github.com/AikidoSec/firewall-go/instrumentation/sinks/os
    template: |
      //go:linkname __aikido_os_Examine github.com/AikidoSec/firewall-go/instrumentation/sinks/os.Examine
      func __aikido_os_Examine(string) error
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	require.Len(t, rules.InjectDeclRules, 1)
	require.Empty(t, rules.WrapRules)
	require.Empty(t, rules.PrependRules)

	assert.Equal(t, "os.linkname", rules.InjectDeclRules[0].ID)
	assert.Equal(t, "os", rules.InjectDeclRules[0].Package)
	assert.Equal(t, "Getpid", rules.InjectDeclRules[0].AnchorFunc)
	assert.Equal(t, []string{"github.com/AikidoSec/firewall-go/instrumentation/sinks/os"}, rules.InjectDeclRules[0].Links)
	assert.Contains(t, rules.InjectDeclRules[0].DeclTemplate, "go:linkname")
}

func TestLoadRulesFromDir_SkipsSubmodulesWithGoMod(t *testing.T) {
	// Simulate the root module's instrumentation/ dir where some subdirectories
	// are separate Go modules (have their own go.mod). These should be skipped
	// to avoid loading their rules twice (they're discovered independently).
	tmpDir := t.TempDir()

	// Create a stdlib sink (part of root module, no go.mod)
	stdlibDir := filepath.Join(tmpDir, "sinks", "os")
	require.NoError(t, os.MkdirAll(stdlibDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(stdlibDir, "zen.instrument.yml"), []byte(`
meta:
  name: os
rules:
  - id: os.rule
    type: prepend
    package: os
    function: OpenFile
    imports: {}
    template: "// instrumented"
`), 0o600))

	// Create a submodule sink (has its own go.mod, should be skipped)
	submoduleDir := filepath.Join(tmpDir, "sinks", "jackc", "pgx.v5")
	require.NoError(t, os.MkdirAll(submoduleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(submoduleDir, "go.mod"), []byte(`
module github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(submoduleDir, "zen.instrument.yml"), []byte(`
meta:
  name: pgx
rules:
  - id: pgx.rule
    type: prepend
    package: pgx
    function: Connect
    imports: {}
    template: "// instrumented"
`), 0o600))

	rules, err := LoadRulesFromDir(tmpDir)
	require.NoError(t, err)

	// Only the stdlib rule should be loaded; pgx should be skipped
	require.Len(t, rules.PrependRules, 1)
	assert.Equal(t, "os.rule", rules.PrependRules[0].ID)
}

func TestLoadRulesFromDir_RootGoModNotSkipped(t *testing.T) {
	// When walking a submodule dir directly (e.g., pgx.v5/), its own go.mod
	// should NOT cause it to be skipped — only subdirectory go.mods are skipped.
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(`
module github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "zen.instrument.yml"), []byte(`
meta:
  name: pgx
rules:
  - id: pgx.rule
    type: prepend
    package: pgx
    function: Connect
    imports: {}
    template: "// instrumented"
`), 0o600))

	rules, err := LoadRulesFromDir(tmpDir)
	require.NoError(t, err)

	require.Len(t, rules.PrependRules, 1)
	assert.Equal(t, "pgx.rule", rules.PrependRules[0].ID)
}

func TestLoadRulesFromFile_AllRuleTypes(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "zen.instrument.yml")

	yamlContent := `
meta:
  name: mixed-all
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
  - id: inject-decl-rule
    type: inject-decl
    package: os
    anchor: Getpid
    links: []
    template: func __test() {}
`
	err := os.WriteFile(yamlPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	rules, err := loadRulesFromFile(yamlPath)
	require.NoError(t, err)
	assert.Len(t, rules.WrapRules, 1)
	assert.Len(t, rules.PrependRules, 1)
	assert.Len(t, rules.InjectDeclRules, 1)
}
