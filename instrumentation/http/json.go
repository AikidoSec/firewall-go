package http

import (
	"bytes"
	"encoding/json"
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

// ExtractJSONFromReader parses JSON values, retaining duplicates for inspection.
func ExtractJSONFromReader(r io.Reader) any {
	decoder := json.NewDecoder(r)
	var results []any
	for {
		data, err := readInspectionJSONValue(decoder, 0)
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
