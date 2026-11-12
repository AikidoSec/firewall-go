package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/AikidoSec/firewall-go/zen"
)

const maxAIResponseBytes = 2 * 1024 * 1024

func captureAIResponse(req *http.Request, resp *http.Response) {
	defer func() { _ = recover() }()
	if !zen.ShouldProtect() {
		return
	}
	if req == nil || req.URL == nil || resp == nil || resp.Body == nil {
		return
	}
	if req.Method != http.MethodPost || !isAIRequestPath(req.URL.EscapedPath()) {
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}
	if resp.ContentLength > maxAIResponseBytes {
		return
	}
	mime := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if mime != "application/json" && !strings.HasSuffix(mime, "+json") {
		return
	}
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if resp.Uncompressed {
		encoding = ""
	}
	switch encoding {
	case "", "identity", "gzip", "deflate":
	default:
		return
	}
	u := *req.URL
	resp.Body = &aiResponseBody{inner: resp.Body, url: &u, encoding: encoding, contentLength: resp.ContentLength}
}

type aiResponseBody struct {
	inner         io.ReadCloser
	url           *url.URL
	encoding      string
	contentLength int64
	mu            sync.Mutex
	data          []byte
	finished      bool
}

func (b *aiResponseBody) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	b.observe(p[:n], err)
	return n, err
}

func (b *aiResponseBody) observe(p []byte, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() {
		if recover() != nil {
			b.finished = true
			b.data = nil
		}
	}()
	if b.finished {
		return
	}
	if len(p) > maxAIResponseBytes-len(b.data) || (err != nil && err != io.EOF) ||
		(err == io.EOF && b.contentLength > 0 && int64(len(b.data)+len(p)) != b.contentLength) {
		b.finished = true
		b.data = nil
		return
	}
	b.data = append(b.data, p...)
	if err == io.EOF || (b.contentLength > 0 && int64(len(b.data)) == b.contentLength) {
		b.finished = true
		data := b.data
		b.data = nil
		if decoded, ok := decodeAIResponse(data, b.encoding); ok {
			if call, ok := parseAIResponse(b.url, decoded); ok {
				call.record()
			}
		}
	}
}

func (b *aiResponseBody) Close() error {
	// Stop capture before closing the body unblocks an in-flight Read.
	b.mu.Lock()
	b.finished = true
	b.data = nil
	b.mu.Unlock()
	return b.inner.Close()
}

func decodeAIResponse(data []byte, encoding string) ([]byte, bool) {
	var reader io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(data))
	default:
		return data, true
	}
	if err != nil {
		return nil, false
	}
	defer func() { _ = reader.Close() }()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxAIResponseBytes+1))
	return decoded, err == nil && len(decoded) <= maxAIResponseBytes
}
