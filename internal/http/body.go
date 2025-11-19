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

// TryExtractBody attempts to extract body data from a request, trying JSON first, then forms
func TryExtractBody(req *http.Request, parser MultipartFormParser) any {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	bodyFromJSON := tryExtractJSON(req)
	if bodyFromJSON != nil {
		return bodyFromJSON
	}

	bodyFromForm := tryExtractFormBody(req, parser)
	if bodyFromForm != nil {
		return bodyFromForm
	}

	// No usable data found, returning nil
	return nil
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
