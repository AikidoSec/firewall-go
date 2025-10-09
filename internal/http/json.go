package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

func TryExtractJSON(r *http.Request) any {
	var buf bytes.Buffer
	tee := io.TeeReader(r.Body, &buf)

	var data any
	err := json.NewDecoder(tee).Decode(&data)

	// Drain any remaining bytes to ensure full body is available in request
	io.Copy(io.Discard, tee)

	r.Body = io.NopCloser(&buf)

	if err != nil {
		return nil
	}

	return data
}
