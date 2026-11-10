package http

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkTryExtractBodyMemory(b *testing.B) {
	for _, sizeMiB := range []int64{1, 16, 64, 256} {
		b.Run(fmt.Sprintf("%dMiB", sizeMiB), func(b *testing.B) {
			size := sizeMiB << 20
			b.ReportAllocs()

			for b.Loop() {
				body := io.LimitReader(benchmarkBodyReader{}, size)
				req := httptest.NewRequest(http.MethodPost, "/noop", body)
				req.ContentLength = size
				req.Header.Set("Content-Type", "application/octet-stream")

				TryExtractBody(req, &mockParser{req: req})

				_ = req.Body.Close()
			}
		})
	}
}

type benchmarkBodyReader struct{}

func (benchmarkBodyReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
