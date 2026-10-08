package http

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/AikidoSec/firewall-go/internal/log"
)

// MaxBodySize defines the maximum request body size that will be buffered
// for inspection before firewall admission checks. This limit prevents
// unauthenticated denial-of-service attacks via unbounded memory allocation.
// Set to 10 MB by default, which accommodates typical API payloads while
// preventing resource exhaustion. Applications requiring larger bodies should
// configure their reverse proxy or load balancer to enforce limits before
// requests reach the application.
const MaxBodySize = 10 * 1024 * 1024 // 10 MB

// MultipartFormParser defines the interface for extracting multipart form data
type MultipartFormParser interface {
	MultipartForm() (*multipart.Form, error)
}

// TryExtractBody attempts to extract body data from a request using both JSON
// and form parsers, returning whichever finds data. Both are always attempted
// so the firewall does not depend on Content-Type to decide what the backend
// will process.
//
// To prevent unauthenticated denial-of-service via unbounded request body
// buffering, this function enforces a maximum body size limit (MaxBodySize).
// Bodies exceeding this limit are not extracted, and the original body stream
// is preserved for the application handler.
func TryExtractBody(req *http.Request, parser MultipartFormParser) any {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	// Wrap the body with a size limit to prevent unbounded memory allocation
	// before firewall admission checks execute. This protects against
	// unauthenticated attackers sending arbitrarily large bodies.
	originalBody := req.Body
	limitedBody := &limitedReadCloser{
		reader: io.LimitReader(originalBody, MaxBodySize+1), // +1 to detect oversized bodies
		closer: originalBody,
	}
	req.Body = limitedBody

	// Buffer the limited body for inspection
	var buf bytes.Buffer
	tee := io.TeeReader(req.Body, &buf)

	// Check if body exceeds limit by attempting to read MaxBodySize+1 bytes
	n, _ := io.Copy(io.Discard, tee)

	// Restore body for subsequent processing
	req.Body = io.NopCloser(&buf)

	// If body exceeds limit, skip extraction to prevent resource exhaustion
	if n > MaxBodySize {
		log.Debug("request body exceeds maximum size for extraction",
			slog.Int64("size", n),
			slog.Int64("limit", MaxBodySize))
		return nil
	}

	bodyFromJSON := tryExtractJSON(req)
	bodyFromForm := tryExtractFormBody(req, parser)

	if bodyFromJSON != nil && bodyFromForm != nil {
		return []any{bodyFromJSON, bodyFromForm}
	}
	if bodyFromJSON != nil {
		return bodyFromJSON
	}
	return bodyFromForm
}

// limitedReadCloser wraps an io.Reader with a Close method
type limitedReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	return l.reader.Read(p)
}

func (l *limitedReadCloser) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// tryExtractFormBody attempts to extract form data (urlencoded or multipart)
// Note: The body has already been buffered and size-limited by TryExtractBody,
// so this function works with the restored body stream.
func tryExtractFormBody(req *http.Request, parser MultipartFormParser) url.Values {
	// Save the current body position
	var buf bytes.Buffer
	originalBody := req.Body

	// Tee the body so we can restore it after parsing
	req.Body = io.NopCloser(io.TeeReader(originalBody, &buf))

	_, err := parser.MultipartForm()

	// Drain any remaining bytes to ensure full body is captured in buffer
	// This is important if MultipartForm fails early without reading everything
	_, _ = io.Copy(io.Discard, req.Body)

	// Restore the body from the buffer
	req.Body = io.NopCloser(&buf)

	if err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debug("error on parse multipart form", slog.Any("error", err))
			return nil
		}
	}

	if len(req.PostForm) == 0 {
		return nil
	}

	return req.PostForm
}
