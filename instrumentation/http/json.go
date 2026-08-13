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

	result := ExtractJSONFromReader(tee)

	// Drain any remaining bytes to ensure full body is available in request
	// Ignore error - we still need to restore the request body
	_, _ = io.Copy(io.Discard, tee)
	r.Body = io.NopCloser(&buf)

	return result
}

func ExtractJSONFromReader(r io.Reader) any {
	decoder := json.NewDecoder(r)
	var results []any
	for {
		var data any
		err := decoder.Decode(&data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		results = append(results, data)
	}

	switch len(results) {
	case 0:
		return nil
	case 1:
		return results[0]
	default:
		return results
	}
}
