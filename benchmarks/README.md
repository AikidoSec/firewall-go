# Benchmarks

Zen is designed to have minimal impact on your application's performance. We run benchmarks on every commit to ensure this remains true.

## Running Benchmarks

```bash
make benchmark
```

This finds all packages containing benchmarks and runs them.

## What We Measure

### Middleware Overhead

We benchmark the middleware for each supported framework to measure the overhead added to HTTP request handling:

- `BenchmarkMiddleware` (gin) - `instrumentation/sources/gin-gonic/gin`
- `BenchmarkMiddleware` (echo) - `instrumentation/sources/labstack/echo.v4`
- `BenchmarkMiddleware` (chi) - `instrumentation/sources/go-chi/chi`

### SQL Injection Detection

- `BenchmarkDetectSQLInjection` - `vulnerabilities/sqlinjection`

Measures the performance of SQL injection detection across various input patterns.

### SQL Sink Overhead with HTTP Request Context

```bash
make bench-sql COUNT=5
BENCH='BenchmarkHTTPSQLSerial/WASM' BENCHTIME=2s make bench-sql COUNT=5
```

`benchmarks/sinks/database/sql` compares vanilla vs. zen-go for HTTP requests
through the SQL sink, using an in-memory driver. Covers early-return and WASM
paths in `BenchmarkHTTPSQLSerial` and `BenchmarkHTTPSQLParallel`. Results and profiles are saved to
`bench-results/benchmarks_sinks_database_sql/`.

Parallel `ns/op` measures throughput rather than request latency. Profiles
include initialization and warmup; per-operation metrics exclude untimed setup.

### Body Parsing

- `BenchmarkSmallBody` (1KB) - `internal/http`
- `BenchmarkLargeBody` (5MB) - `internal/http`

Measures JSON body parsing performance for different payload sizes.

### IP Block/Allow Lists

- `BenchmarkBuildMatchList` - `internal/agent/ipaddr`
- `BenchmarkMatchList_Matches` - `internal/agent/ipaddr`

Measures building a `MatchList` and looking up an address against one.

## CI

Benchmarks run automatically on every push to `main` and on pull requests. Results are displayed in the GitHub Actions job summary.
