//go:build runtime_bench

// Micro-benchmarks for goroutine-spawn overhead added by the runtime patch.
// Run via: TAGS=runtime_bench scripts/bench-toolexec.sh ./benchmarks/runtime

package runtimebench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/internal/request"
)

// TestCompiledWithZenGo is the liveness gate: passes only under zen-go toolexec.
func TestCompiledWithZenGo(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/verify", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "bench-verify",
		Route:         "/verify",
		RemoteAddress: &ip,
	})

	type result struct {
		ctx *request.Context
	}
	out := make(chan result, 1)

	request.WrapWithGLS(ctx, func() {
		go func() {
			out <- result{ctx: request.GetContext(context.Background())}
		}()
		select {
		case r := <-out:
			if r.ctx == nil {
				t.Fatal("child goroutine saw no request context — runtime instrumentation is not active; " +
					"re-run with -toolexec=\"$(pwd)/tools/bin/zen-go toolexec\"")
			}

		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for child goroutine")
		}
	})
}

func BenchmarkSpawn(b *testing.B) {
	var wg sync.WaitGroup
	wg.Add(b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go wg.Done()
	}
	wg.Wait()
}

func BenchmarkSpawnParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		var wg sync.WaitGroup
		for pb.Next() {
			wg.Add(1)
			go wg.Done()
		}
		wg.Wait()
	})
}

func BenchmarkSpawnFanOut(b *testing.B) {
	const fanout = 16
	var wg sync.WaitGroup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(fanout)
		for j := 0; j < fanout; j++ {
			go wg.Done()
		}
		wg.Wait()
	}
}

// BenchmarkGetContext uses context.Background() to force the GLS fallback path.
func BenchmarkGetContext(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/bench", http.NoBody)
	ip := "127.0.0.1"
	ctx := request.SetContext(context.Background(), req, request.ContextData{
		Source:        "bench",
		Route:         "/bench",
		RemoteAddress: &ip,
	})

	request.WrapWithGLS(ctx, func() {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = request.GetContext(context.Background())
		}
	})
}
