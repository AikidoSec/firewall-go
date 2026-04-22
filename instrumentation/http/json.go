package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func tryExtractJSON(r *http.Request) any {
	var buf bytes.Buffer
	tee := io.TeeReader(r.Body, &buf)

	decoder := json.NewDecoder(tee)
	var results []any
	for {
		var data any
		err := decoder.Decode(&data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_, _ = io.Copy(io.Discard, tee)
			r.Body = io.NopCloser(&buf)
			return nil
		}
		results = append(results, data)
	}

	// Drain any remaining bytes to ensure full body is available in request
	// Ignore error - we still need to restore the request body
	_, _ = io.Copy(io.Discard, tee)
	r.Body = io.NopCloser(&buf)

	switch len(results) {
	case 0:
		return nil
	case 1:
		return results[0]
	default:
		return results
	}
}
