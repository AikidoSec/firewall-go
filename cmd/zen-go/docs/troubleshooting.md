# Troubleshooting

## Enabling debug logging

Set `ZENGO_DEBUG=true` to enable debug logging. Use `ZENGO_LOG=<path>` to write logs to a file - this is recommended because some stdout output is suppressed by the Go toolchain spawning multiple subprocesses.

Since zen-go only runs on uncached compilations, clear the Go build cache first to ensure you see the logs:

```bash
go clean -cache
```

## Common build errors

**Fingerprint errors** can occur when the Go build cache is stale. This typically happens when developing the zen-go CLI locally. To fix, clear the cache:

```bash
go clean -cache
```
