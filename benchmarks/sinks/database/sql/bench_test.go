//go:build sink_bench

package sqlbench

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/zeninternals"
	"github.com/AikidoSec/firewall-go/zen"
)

func init() {
	sql.Register("bench-postgres", postgresDriver{})
}

// Only the database transport is replaced: database/sql pooling and injected
// SQL examination still execute normally. No SQL parsing occurs in this driver.
type postgresDriver struct{}

func (postgresDriver) Open(string) (driver.Conn, error) { return &benchConn{}, nil }

type benchConn struct{}

func (*benchConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("prepare is not used") }
func (*benchConn) Close() error                        { return nil }
func (*benchConn) Begin() (driver.Tx, error)           { return nil, errors.New("transactions are not used") }
func (*benchConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

// Keep operation accounting active, matching the runtime registered by Protect,
// without starting cloud polling or network goroutines in the benchmark process.
type benchRuntime struct{}

func (benchRuntime) OnOperationCall(op string, kind operation.Kind) {
	agent.Stats().OnOperationCall(op, kind)
}

func (benchRuntime) OnDomain(string, uint32)           {}
func (benchRuntime) ShouldBlockHostname(string) bool   { return false }
func (benchRuntime) OnAICall(string, string, int, int) {}

func setup(b testing.TB) *sql.DB {
	b.Helper()
	zen.SetDisabled(false)
	if err := config.Init(&aikido_types.EnvironmentConfigData{}, &aikido_types.AikidoConfigData{LogLevel: "ERROR"}); err != nil {
		b.Fatal(err)
	}
	if err := zeninternals.Init(); err != nil {
		b.Fatal(err)
	}
	config.SetZenLoaded(true)
	config.SetBlocking(true)
	hooks.Register(benchRuntime{})
	b.Cleanup(func() { config.SetZenLoaded(false) })
	db, err := sql.Open("bench-postgres", "")
	if err != nil {
		b.Fatal(err)
	}
	db.SetMaxIdleConns(runtime.GOMAXPROCS(0))
	b.Cleanup(func() {
		if err := db.Close(); err != nil {
			b.Error(err)
		}
	})
	return db
}

func handler(db *sql.DB, parameterized bool, observe func(*http.Request, error)) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		query := "SELECT * FROM users WHERE name = '" + name + "'"
		var err error
		if parameterized {
			_, err = db.ExecContext(r.Context(), "SELECT * FROM users WHERE name = $1", name)
		} else {
			_, err = db.ExecContext(r.Context(), query)
		}
		if observe != nil {
			observe(r, err)
		}
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// This gate runs only in the zen-go binary. It checks actual context extraction
// and a blocked injection, rather than just the compilation marker.
func TestCompiledWithZenGo(t *testing.T) {
	if !config.IsCompiledWithZenGo() {
		t.Fatal("re-run with zen-go toolexec; HTTP and SQL instrumentation are required")
	}
	db := setup(t)
	const payload = "1' OR 1=1 --"
	var observed bool
	mux := handler(db, false, func(r *http.Request, err error) {
		observed = true
		ctx := request.GetContext(r.Context())
		if ctx == nil || url.Values(ctx.Query).Get("name") != payload {
			t.Error("HTTP instrumentation did not capture the query input")
		}
		var blocked *zen.AttackBlockedError
		if !errors.As(err, &blocked) {
			t.Errorf("SQL instrumentation did not block injection: %v", err)
		}
	})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users?name="+url.QueryEscape(payload), http.NoBody))
	if !observed || w.Code != http.StatusForbidden {
		t.Fatalf("handler observed=%t, status=%d; want SQL handler to block with 403", observed, w.Code)
	}
}

func BenchmarkHTTPSQLSerial(b *testing.B) {
	benchmarkHTTPSQL(b, func(b *testing.B, serve func() bool) {
		for range b.N {
			if !serve() {
				b.Fatal("safe request failed")
			}
		}
	})
}

func BenchmarkHTTPSQLParallel(b *testing.B) {
	benchmarkHTTPSQL(b, func(b *testing.B, serve func() bool) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if !serve() {
					b.Error("safe request failed")
					return
				}
			}
		})
	})
}

func benchmarkHTTPSQL(b *testing.B, run func(*testing.B, func() bool)) {
	b.Helper()
	db := setup(b)
	// Exercise the production pool during asynchronous compilation. Warmup is
	// untimed and separate from the request samples.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := zeninternals.DetectSQLInjection("SELECT * FROM users WHERE name = 'alice-smith'", "alice-smith", int(zeninternals.PostgreSQL)); got != 0 {
			b.Fatalf("WASM warmup returned %d", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, input := range []struct {
		name          string
		value         string
		parameterized bool
	}{
		{"Alphanumeric", "alice", false},
		{"Parameterized", "alice-smith", true},
		{"WASM", "alice-smith", false},
		{"LargeWASM", strings.Repeat("alice-smith ", 372), false},
	} {
		b.Run(input.name, func(b *testing.B) {
			mux := handler(db, input.parameterized, nil)
			path := "/users?name=" + url.QueryEscape(input.value)
			serve := func() bool {
				// Fresh requests avoid retaining request-local scan state.
				r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				return w.Code == http.StatusNoContent
			}
			if !serve() {
				b.Fatal("safe request failed during warmup")
			}
			b.ReportAllocs()
			b.ResetTimer()
			run(b, serve)
		})
	}
}
