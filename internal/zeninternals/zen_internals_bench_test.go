package zeninternals

import (
	"strings"
	"testing"
	"time"
)

var sqlInjectionBenchmarkInputs = []struct {
	name  string
	query string
	input string
	want  int
}{
	{"Safe", "SELECT * FROM users WHERE name = 'alice'", "alice", 0},
	{"Parameterized", "SELECT * FROM users WHERE name = $1", "alice", 0},
	{"Injection", "SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", 1},
	{"LargeSafe", "SELECT * FROM users WHERE name = '" + strings.Repeat("a", 4096) + "'", strings.Repeat("a", 4096), 0},
}

func BenchmarkDetectSQLInjectionSerial(b *testing.B) {
	benchmarkDetectSQLInjection(b, func(b *testing.B, detect func() bool) {
		for range b.N {
			if !detect() {
				b.Fatal("unexpected detection result")
			}
		}
	})
}

func BenchmarkDetectSQLInjectionParallel(b *testing.B) {
	benchmarkDetectSQLInjection(b, func(b *testing.B, detect func() bool) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !detect() {
					b.Error("unexpected detection result")
					return
				}
			}
		})
	})
}

// Exercise the public API and real pool. Waiting for compilation avoids mixing
// startup and steady-state execution in a sample.
func benchmarkDetectSQLInjection(b *testing.B, run func(*testing.B, func() bool)) {
	b.Helper()
	if err := Init(); err != nil {
		b.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for !hasCompileFinished() {
		if time.Now().After(deadline) {
			b.Fatal("WASM compilation did not complete within 30s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, input := range sqlInjectionBenchmarkInputs {
		b.Run(input.name, func(b *testing.B) {
			// An injection probe also catches the API's fail-open error result.
			probe := sqlInjectionBenchmarkInputs[2]
			if got := DetectSQLInjection(probe.query, probe.input, int(PostgreSQL)); got != probe.want {
				b.Fatalf("warmup injection probe: got %d, want %d", got, probe.want)
			}
			if got := DetectSQLInjection(input.query, input.input, int(PostgreSQL)); got != input.want {
				b.Fatalf("warmup: got %d, want %d", got, input.want)
			}
			detect := func() bool {
				return DetectSQLInjection(input.query, input.input, int(PostgreSQL)) == input.want
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(input.query) + len(input.input)))
			b.ResetTimer()
			run(b, detect)
		})
	}
}
