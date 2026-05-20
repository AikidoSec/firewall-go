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

// MultipartFormParser defines the interface for extracting multipart form data
type MultipartFormParser interface {
	MultipartForm() (*multipart.Form, error)
}

// TryExtractBody attempts to extract body data from a request using both JSON
// and form parsers, returning whichever finds data. Both are always attempted
// so the firewall does not depend on Content-Type to decide what the backend
// will process.
//
// The second return value is true when the JSON body contained duplicate object
// member names — a known detection-bypass pattern (see AIKIDO-UQJ4BZHJ).
func TryExtractBody(req *http.Request, parser MultipartFormParser) (any, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, false
	}

	bodyFromJSON, hasDuplicateKeys := tryExtractJSON(req)
	if hasDuplicateKeys {
		// Don't attempt form extraction: the JSON body is already an attack.
		return nil, true
	}

	bodyFromForm := tryExtractFormBody(req, parser)

	if bodyFromJSON != nil && bodyFromForm != nil {
		return []any{bodyFromJSON, bodyFromForm}, false
	}
	if bodyFromJSON != nil {
		return bodyFromJSON, false
	}
	return bodyFromForm, false
}

// tryExtractFormBody attempts to extract form data (urlencoded or multipart)
func tryExtractFormBody(req *http.Request, parser MultipartFormParser) url.Values {
	// Use TeeReader to preserve the body while MultipartForm consumes it
	var buf bytes.Buffer

	originalBody := req.Body
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
