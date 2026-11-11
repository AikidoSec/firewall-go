package http

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/AikidoSec/firewall-go/internal/log"
)

// TryExtractBody attempts to extract body data from a request using both JSON
// and form parsers, returning whichever finds data. Both are always attempted
// so the firewall does not depend on Content-Type to decide what the backend
// will process.
func TryExtractBody(req *http.Request) any {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	originalBody := req.Body
	var buf bytes.Buffer
	tee := io.TeeReader(originalBody, &buf)
	bodyFromJSON := ExtractJSONFromReader(tee)

	// Drain any remaining bytes to ensure full body is available in request.
	// Ignore error - we still need to restore the request body.
	_, _ = io.Copy(io.Discard, tee)
	body := buf.Bytes()

	req.Body = &replayBody{Reader: bytes.NewReader(body), Closer: originalBody}

	// Parse only a private request so downstream middleware can still control
	// the application's form parsing. Clone copies existing form state, which
	// must be cleared on the inspection copy to inspect the captured body.
	inspectionReq := req.Clone(req.Context())
	inspectionReq.Body = io.NopCloser(bytes.NewReader(body))
	inspectionReq.Form = nil
	inspectionReq.PostForm = nil
	inspectionReq.MultipartForm = nil
	bodyFromForm := tryExtractFormBody(inspectionReq)

	if bodyFromJSON != nil && bodyFromForm != nil {
		return []any{bodyFromJSON, bodyFromForm}
	}
	if bodyFromJSON != nil {
		return bodyFromJSON
	}
	return bodyFromForm
}

// replayBody reads captured bytes while preserving the original body's Close.
type replayBody struct {
	io.Reader
	io.Closer
}

// tryExtractFormBody attempts to extract form data (urlencoded or multipart)
func tryExtractFormBody(req *http.Request) url.Values {
	err := req.ParseMultipartForm(32 << 20)
	if req.MultipartForm != nil {
		defer req.MultipartForm.RemoveAll()
	}
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		log.Debug("error on parse multipart form", slog.Any("error", err))
		return nil
	}

	if len(req.PostForm) == 0 {
		return nil
	}

	return req.PostForm
}
