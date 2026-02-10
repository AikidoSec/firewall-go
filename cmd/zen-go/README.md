# zen-go

CLI build tool for [Aikido Zen for Go](../../README.md). It instruments your Go application at compile time using Go's `-toolexec` flag to intercept and monitor operations like database queries and system calls.

## Usage

Install:

```bash
go install github.com/AikidoSec/firewall-go/cmd/zen-go@latest
```

Initialize your project (creates `zen.tool.go`):

```bash
zen-go init
```

Build with instrumentation:

```bash
go build -toolexec="zen-go toolexec" -o bin/app .
```

## How it works

`zen-go` hooks into the Go compiler and linker via `-toolexec`. During compilation, it applies instrumentation rules defined in `zen.instrument.yml` files to inject security checks into your application. A hash of these rules is included in the build ID, so Go only rebuilds packages when rules change.

## Acknowledgements

Inspired by Datadog's [Orchestrion](https://github.com/DataDog/orchestrion) and Alibaba's [Loongsuite Go Agent](https://github.com/alibaba/opentelemetry-go-auto-instrumentation).
