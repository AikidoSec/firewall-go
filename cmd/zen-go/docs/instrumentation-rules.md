# Instrumentation Rules

zen-go transforms Go code at compile time using rules defined in `zen.instrument.yml` files. Each instrumentation package (source or sink) contains one of these files describing how to inject code.

## File Structure

```yaml
meta:
  name: my-package
  description: What this instrumentation does.
  min-zen-go-version: 0.2.0  # optional

rules:
  - id: unique.rule.id
    type: wrap | prepend | inject-decl
    # ... type-specific fields
    imports:
      alias: import/path
    template: |
      # Go code to inject
```

The `meta` section is informational, except for `min-zen-go-version` which causes a build error if the installed zen-go is too old.

## Rule Types

### `wrap`

Replaces a function call expression with a wrapper. Used to auto-inject middleware into framework setup calls.

| Field | Description |
|---|---|
| `match` | Fully qualified function to match, e.g. `github.com/gin-gonic/gin.Default` |
| `exclude` | Optional list of packages where the rule should not apply |
| `imports` | Imports needed by the template |
| `template` | Go expression that wraps the original call. `{{.}}` is replaced with the original call |

**Example** — auto-register middleware on `gin.Default()`:

```yaml
- id: gin.Default
  type: wrap
  match: github.com/gin-gonic/gin.Default
  imports:
    zengin: github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin
  template: |
    func() *gin.Engine { e := {{.}}; e.Use(zengin.GetMiddleware()); return e }()
```

### `prepend`

Injects statements at the beginning of a function body. Used to add security checks before operations like database queries or file access.

| Field | Description |
|---|---|
| `receiver` | Receiver type for methods, e.g. `*database/sql.DB` |
| `package` | Package name for standalone functions, e.g. `os` |
| `function` | Single function name to match |
| `functions` | List of function names to match (alternative to `function`) |
| `imports` | Imports needed by the template |
| `template` | Go statements to prepend. Supports template variables (see below) |

**Template variables:**

- `{{ .Function.Argument N }}` — name of the Nth parameter (0-indexed)
- `{{ .Function.Receiver }}` — name of the receiver variable
- `{{ .Function.Name }}` — name of the function

**Example** — check SQL queries before execution:

```yaml
- id: database/sql.DB.QueryContext
  type: prepend
  receiver: "*database/sql.DB"
  function: QueryContext
  imports:
    sink: github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql
  template: |
    _aikido_block := sink.ExamineContext({{ .Function.Argument 0 }}, {{ .Function.Argument 1 }}, "database/sql.DB.QueryContext")
    if _aikido_block != nil {
      return nil, _aikido_block
    }
```

### `inject-decl`

Injects function declarations before an anchor function in a package. Typically used with `//go:linkname` to bridge into stdlib packages where you can't add imports.

| Field | Description |
|---|---|
| `package` | The package being compiled, e.g. `os` |
| `anchor` | An existing function in the package to attach the declaration before |
| `links` | Packages that must be linked for the injected declarations to resolve |
| `template` | Go declarations to inject (usually `//go:linkname` + function signature) |

**Example** — make `os` package callable to the security check in the sink:

```yaml
- id: os.Examine.linkname
  type: inject-decl
  package: os
  anchor: Getpid
  links:
    - github.com/AikidoSec/firewall-go/instrumentation/sinks/os
  template: |
    //go:linkname __aikido_os_Examine github.com/AikidoSec/firewall-go/instrumentation/sinks/os.Examine
    func __aikido_os_Examine(string) error
```

This is often paired with a `prepend` rule in the same file that calls the injected function:

```yaml
- id: os.OpenFile
  type: prepend
  package: os
  function: OpenFile
  template: |
    _aikido_block := __aikido_os_Examine({{ .Function.Argument 0 }})
    if _aikido_block != nil {
      return nil, _aikido_block
    }
```

## Discovery

zen-go automatically discovers all `zen.instrument.yml` files from:

1. The main module's `instrumentation/` directory
2. Any submodule directories matching `github.com/AikidoSec/firewall-go/instrumentation/...`

Rules from all discovered files are merged and applied during compilation.
