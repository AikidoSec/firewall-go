//go:build sink_bench

// Benchmarks for the os sink (path-traversal scan injected into os.OpenFile).
// Run via scripts/bench-toolexec.sh for the vanilla vs. zen-go comparison.

package osbench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
)

// TestCompiledWithZenGo is the liveness gate: passes only under zen-go toolexec.
func TestCompiledWithZenGo(t *testing.T) {
	if !config.IsCompiledWithZenGo() {
		t.Fatal("binary was not compiled with zen-go; re-run with " +
			`-toolexec="$(pwd)/tools/bin/zen-go toolexec"`)
	}
}

func benchFile(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "bench.txt")
	if err := os.WriteFile(path, []byte("zen"), 0o600); err != nil {
		b.Fatal(err)
	}
	return path
}

func openClose(b *testing.B, path string) {
	b.Helper()
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	_ = f.Close()
}

func BenchmarkOpenFile(b *testing.B) {
	// Enable the scan path without starting the agent (zen.Protect spawns
	// network goroutines).
	config.SetZenLoaded(true)
	b.Cleanup(func() { config.SetZenLoaded(false) })

	path := benchFile(b)

	b.Run("no_context", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			openClose(b, path)
		}
	})

	b.Run("with_context", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/files?name=report&id=42", http.NoBody)
		ip := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "bench",
			Route:         "/files",
			RemoteAddress: &ip,
		})

		b.ResetTimer()
		request.WrapWithGLS(ctx, func() {
			for i := 0; i < b.N; i++ {
				openClose(b, path)
			}
		})
	})
}
