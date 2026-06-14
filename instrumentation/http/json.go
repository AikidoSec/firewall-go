package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-json-experiment/json/jsontext"
)

// tryExtractJSON parses the request body as a sequence of JSON values.
// hasDuplicateKeys is true when the body contained duplicate JSON object member
// names — a known bypass pattern where an attacker overrides a malicious field
// value with null so the firewall sees null while the backend sees the original.
func tryExtractJSON(r *http.Request) (data any, hasDuplicateKeys bool) {
	var buf bytes.Buffer
	tee := io.TeeReader(r.Body, &buf)

	// jsontext.NewDecoder rejects duplicate object member names by default
	// (AllowDuplicateNames is false unless explicitly opted in).
	dec := jsontext.NewDecoder(tee)
	var results []any
	for {
		raw, err := dec.ReadValue()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var serr *jsontext.SyntacticError
			if errors.As(err, &serr) && serr.Err == jsontext.ErrDuplicateName {
				hasDuplicateKeys = true
			}
			break
		}
		// Safe to use encoding/json here: ReadValue already validated that
		// the value contains no duplicate keys.
		var val any
		_ = json.Unmarshal([]byte(raw), &val)
		results = append(results, val)
	}

	// Drain any remaining bytes to ensure full body is available in request.
	// Ignore error - we still need to restore the request body.
	_, _ = io.Copy(io.Discard, tee)
	r.Body = io.NopCloser(&buf)

	switch len(results) {
	case 0:
		return nil, hasDuplicateKeys
	case 1:
		return results[0], hasDuplicateKeys
	default:
		return results, hasDuplicateKeys
	}
}
