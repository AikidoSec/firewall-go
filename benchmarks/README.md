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

- `BenchmarkDetectSQLInjection` - `internal/vulnerabilities/sqlinjection`

Measures the performance of SQL injection detection across various input patterns.

### Body Parsing

- `BenchmarkSmallBody` (1KB) - `internal/http`
- `BenchmarkLargeBody` (5MB) - `internal/http`

Measures JSON body parsing performance for different payload sizes.

## CI

Benchmarks run automatically on every push to `main` and on pull requests. Results are displayed in the GitHub Actions job summary.
