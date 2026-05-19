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
		data, err := decodeJSONValue(decoder)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
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

// decodeJSONValue reads the next JSON value from dec, collecting all values for
// duplicate object keys into a []any so the detection layer inspects every value
// the client supplied (not just the last one, which map assignment would keep).
func decodeJSONValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}

	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			return decodeJSONObject(dec)
		case '[':
			return decodeJSONArray(dec)
		}
	}
	// Primitives (bool, float64, string) and null (nil) are returned as-is.
	return token, nil
}

func decodeJSONObject(dec *json.Decoder) (map[string]any, error) {
	result := make(map[string]any)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyToken.(string)

		value, err := decodeJSONValue(dec)
		if err != nil {
			return nil, err
		}

		if existing, exists := result[key]; exists {
			// Accumulate duplicate key values so detection sees all of them.
			if slice, ok := existing.([]any); ok {
				result[key] = append(slice, value)
			} else {
				result[key] = []any{existing, value}
			}
		} else {
			result[key] = value
		}
	}
	// consume closing '}'
	_, err := dec.Token()
	return result, err
}

func decodeJSONArray(dec *json.Decoder) ([]any, error) {
	result := make([]any, 0)
	for dec.More() {
		value, err := decodeJSONValue(dec)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	// consume closing ']'
	_, err := dec.Token()
	return result, err
}
