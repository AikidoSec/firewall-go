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
func TryExtractBody(req *http.Request, parser MultipartFormParser) any {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	var buf bytes.Buffer
	tee := io.TeeReader(req.Body, &buf)
	bodyFromJSON := ExtractJSONFromReader(tee)

	// Drain any remaining bytes to ensure full body is available in request.
	// Ignore error - we still need to restore the request body.
	_, _ = io.Copy(io.Discard, tee)
	body := buf.Bytes()

	req.Body = io.NopCloser(bytes.NewReader(body))
	bodyFromForm := tryExtractFormBody(req, parser)
	req.Body = io.NopCloser(bytes.NewReader(body))

	if bodyFromJSON != nil && bodyFromForm != nil {
		return []any{bodyFromJSON, bodyFromForm}
	}
	if bodyFromJSON != nil {
		return bodyFromJSON
	}
	return bodyFromForm
}

// tryExtractFormBody attempts to extract form data (urlencoded or multipart)
func tryExtractFormBody(req *http.Request, parser MultipartFormParser) url.Values {
	_, err := parser.MultipartForm()
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		log.Debug("error on parse multipart form", slog.Any("error", err))
		return nil
	}

	if len(req.PostForm) == 0 {
		return nil
	}

	return req.PostForm
}
