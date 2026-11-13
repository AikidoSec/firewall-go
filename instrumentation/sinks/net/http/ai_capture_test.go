//go:build !integration

package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const aiTestJSON = `{"model":"gpt-4o","choices":[{"message":{"content":"Hi 👋"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`

func setupAICapture(t *testing.T) *stats.Stats {
	t.Helper()

	disabled := zen.IsDisabled()
	zen.SetDisabled(false)
	t.Cleanup(func() { zen.SetDisabled(disabled) })
	require.NoError(t, zen.Protect())

	r := agent.Stats()
	r.GetAndClearAI()
	t.Cleanup(func() { r.GetAndClearAI() })

	return r
}

func TestCaptureAIResponse(t *testing.T) {
	r := setupAICapture(t)
	req := httptest.NewRequest("POST", "https://api.openai.com/proxy/v1/chat/completions?key=secret", nil)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(aiTestJSON)),
		ContentLength: -1,
	}

	captureAIResponse(req, resp)
	assert.Empty(t, r.GetAndClearAI(), "capture must not eagerly consume the body")

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, aiTestJSON, string(data))
	calls := r.GetAndClearAI()
	require.Len(t, calls, 1)
	assert.Equal(t, stats.AIProviderStats{
		Provider: "https://api.openai.com",
		Model:    "gpt-4o",
		Calls:    1,
		Tokens:   stats.AITokenStats{Input: 10, Output: 5, Total: 15},
	}, calls[0])

	_, _ = resp.Body.Read(make([]byte, 10))
	assert.Empty(t, r.GetAndClearAI(), "subsequent reads must not record the call again")
}

func TestCaptureFilters(t *testing.T) {
	r := setupAICapture(t)

	cases := []struct {
		name, method, path, contentType, encoding string
		status                                    int
		length                                    int64
	}{
		{"get", "GET", "/v1/responses", "application/json", "", 200, -1},
		{"path", "POST", "/v1/embeddings", "application/json", "", 200, -1},
		{"status", "POST", "/v1/responses", "application/json", "", 429, -1},
		{"sse", "POST", "/v1/responses", "text/event-stream", "", 200, -1},
		{"encoding", "POST", "/v1/responses", "application/json", "br", 200, -1},
		{"length", "POST", "/v1/responses", "application/json", "", 200, maxAIResponseBytes + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://api.openai.com"+tc.path, nil)
			body := io.NopCloser(strings.NewReader(aiTestJSON))
			defer body.Close()

			resp := &http.Response{
				StatusCode:    tc.status,
				Body:          body,
				ContentLength: tc.length,
				Header: http.Header{
					"Content-Type":     {tc.contentType},
					"Content-Encoding": {tc.encoding},
				},
			}

			captureAIResponse(req, resp)

			assert.Equal(t, body, resp.Body)
			assert.Empty(t, r.GetAndClearAI())
		})
	}

	t.Run("disabled", func(t *testing.T) {
		zen.SetDisabled(true)
		t.Cleanup(func() { zen.SetDisabled(false) })

		req := httptest.NewRequest("POST", "https://api.openai.com/v1/responses", nil)
		body := io.NopCloser(strings.NewReader(aiTestJSON))
		defer body.Close()
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/json"}},
			Body:          body,
			ContentLength: -1,
		}

		captureAIResponse(req, resp)

		assert.Equal(t, body, resp.Body)
	})

	t.Run("nil-body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "https://api.openai.com/v1/responses", nil)
		resp := &http.Response{StatusCode: http.StatusOK}

		captureAIResponse(req, resp)

		assert.Nil(t, resp.Body)
	})

	assert.Empty(t, r.GetAndClearAI())
}

func TestAIBodySplitReadsAndCompletion(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://user:password@api.openai.com/v1/chat/completions?key=secret#secret")
	b := &aiResponseBody{
		inner:         io.NopCloser(strings.NewReader(aiTestJSON)),
		url:           u,
		contentLength: int64(len(aiTestJSON)),
	}

	buf := make([]byte, 1)
	var result []byte

	for range len(aiTestJSON) {
		n, err := b.Read(buf)
		require.NoError(t, err)

		result = append(result, buf[:n]...)
		buf[0] = 0
	}
	require.NoError(t, b.Close())

	assert.Equal(t, aiTestJSON, string(result))
	calls := r.GetAndClearAI()
	require.Len(t, calls, 1, "known Content-Length does not require a subsequent EOF read")
	assert.Equal(t, "https://api.openai.com", calls[0].Provider)
}

func TestAIBodyDiscardsInvalidAndOversized(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://api.openai.com/v1/chat/completions")

	cases := []struct{ name, data string }{
		{"invalid JSON", `{"model":`},
		{"oversized", strings.Repeat(" ", maxAIResponseBytes) + aiTestJSON},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &aiResponseBody{inner: io.NopCloser(strings.NewReader(tc.data)), url: u, contentLength: -1}
			defer b.Close()

			got, err := io.ReadAll(b)
			require.NoError(t, err)

			assert.Equal(t, tc.data, string(got))
			assert.Nil(t, b.data)
			assert.Empty(t, r.GetAndClearAI())
		})
	}
}

func TestAIBodyDiscardsEarlyClose(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://api.openai.com/v1/chat/completions")
	b := &aiResponseBody{inner: io.NopCloser(strings.NewReader(aiTestJSON)), url: u, contentLength: -1}

	_, err := b.Read(make([]byte, 10))
	require.NoError(t, err)
	require.NoError(t, b.Close())

	assert.Nil(t, b.data)
	assert.Empty(t, r.GetAndClearAI())
}

func TestAIBodyCompressed(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://api.openai.com/v1/chat/completions")

	for _, encoding := range []string{"gzip", "deflate"} {
		var encoded bytes.Buffer
		var writer io.WriteCloser
		if encoding == "gzip" {
			writer = gzip.NewWriter(&encoded)
		} else {
			writer = zlib.NewWriter(&encoded)
		}

		_, err := io.WriteString(writer, aiTestJSON)
		require.NoError(t, err)
		require.NoError(t, writer.Close())

		b := &aiResponseBody{
			inner:         io.NopCloser(bytes.NewReader(encoded.Bytes())),
			url:           u,
			encoding:      encoding,
			contentLength: -1,
		}

		got, err := io.ReadAll(b)
		require.NoError(t, err)

		assert.Equal(t, encoded.Bytes(), got, "application still receives encoded bytes")
		_ = b.Close()
	}

	calls := r.GetAndClearAI()
	require.Len(t, calls, 1)
	assert.Equal(t, 2, calls[0].Calls)
}

func TestDecodeAIResponseRejectsInvalidCompression(t *testing.T) {
	for _, encoding := range []string{"gzip", "deflate"} {
		t.Run(encoding, func(t *testing.T) {
			_, ok := decodeAIResponse([]byte("invalid"), encoding)

			assert.False(t, ok)
		})
	}
}

func TestDecodeAIResponseLimitsDecompressedSize(t *testing.T) {
	var bomb bytes.Buffer
	w := gzip.NewWriter(&bomb)
	_, err := io.WriteString(w, strings.Repeat("a", maxAIResponseBytes+1))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	_, ok := decodeAIResponse(bomb.Bytes(), "gzip")

	assert.False(t, ok)
}

type aiErrorBody struct{ err error }

func (b aiErrorBody) Read(p []byte) (int, error) { return copy(p, aiTestJSON), b.err }
func (b aiErrorBody) Close() error               { return b.err }

func TestAIBodyPreservesErrors(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://api.openai.com/v1/chat/completions")
	sentinel := errors.New("read error")
	b := &aiResponseBody{inner: aiErrorBody{sentinel}, url: u}
	buf := make([]byte, len(aiTestJSON))

	n, err := b.Read(buf)

	assert.Equal(t, len(aiTestJSON), n)
	assert.ErrorIs(t, err, sentinel)
	assert.ErrorIs(t, b.Close(), sentinel)
	assert.Empty(t, r.GetAndClearAI())
}

func TestAIBodyRecordsBytesWithEOF(t *testing.T) {
	r := setupAICapture(t)
	u, _ := url.Parse("https://api.openai.com/v1/chat/completions")
	b := &aiResponseBody{inner: aiErrorBody{io.EOF}, url: u, contentLength: -1}
	defer b.Close()

	n, err := b.Read(make([]byte, len(aiTestJSON)))

	assert.Equal(t, len(aiTestJSON), n)
	assert.Equal(t, io.EOF, err)

	calls := r.GetAndClearAI()
	require.Len(t, calls, 1)
	assert.Equal(t, 10, calls[0].Tokens.Input)
}

func TestAIBodyRecoversMonitoringPanics(t *testing.T) {
	r := setupAICapture(t)

	// A nil URL triggers a panic in monitoring, not in the underlying reader.
	b := &aiResponseBody{inner: io.NopCloser(strings.NewReader(aiTestJSON)), contentLength: -1}
	defer b.Close()

	got, err := io.ReadAll(b)
	require.NoError(t, err)

	assert.Equal(t, aiTestJSON, string(got))
	assert.Nil(t, b.data)
	assert.Empty(t, r.GetAndClearAI())
}

type aiBlockingBody struct {
	io.ReadCloser
	started chan struct{}
}

func (b aiBlockingBody) Read(p []byte) (int, error) {
	close(b.started)
	return b.ReadCloser.Read(p)
}

func TestAIBodyConcurrentClose(t *testing.T) {
	u, _ := url.Parse("https://api.openai.com/v1/responses")
	reader, writer := io.Pipe()
	started := make(chan struct{})
	b := &aiResponseBody{inner: aiBlockingBody{reader, started}, url: u, contentLength: -1}

	var wg sync.WaitGroup
	var readErr error
	wg.Go(func() { _, readErr = b.Read(make([]byte, 10)) })
	<-started

	require.NoError(t, b.Close())
	wg.Wait()

	assert.ErrorIs(t, readErr, io.ErrClosedPipe)
	assert.True(t, b.finished)
	assert.Nil(t, b.data)
	_ = writer.Close()
}
