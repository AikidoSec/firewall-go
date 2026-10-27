package http

import (
	"encoding/json"
	"errors"
)

// Match encoding/json's nesting limit.
const maxJSONInspectionDepth = 10000

// readInspectionJSONValue retains duplicate member values in arrays for scanning.
func readInspectionJSONValue(dec *json.Decoder, depth int) (any, error) {
	token, tokenErr := dec.Token()
	if tokenErr != nil {
		return nil, tokenErr
	}
	if token == json.Delim('{') || token == json.Delim('[') {
		if depth >= maxJSONInspectionDepth {
			return nil, errors.New("JSON body exceeds maximum nesting depth")
		}
		depth++
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		// Distinguish duplicate groups from original JSON arrays.
		var grouped map[string]bool
		for dec.More() {
			name, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := name.(string)
			value, err := readInspectionJSONValue(dec, depth)
			if err != nil {
				return nil, err
			}
			if previous, exists := object[key]; exists {
				if grouped[key] {
					object[key] = append(previous.([]any), value)
				} else {
					object[key] = []any{previous, value}
					if grouped == nil {
						grouped = make(map[string]bool)
					}
					grouped[key] = true
				}
			} else {
				object[key] = value
			}
		}
		_, err := dec.Token() // closing brace
		return object, err
	case json.Delim('['):
		array := make([]any, 0)
		for dec.More() {
			value, err := readInspectionJSONValue(dec, depth)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := dec.Token() // closing bracket
		return array, err
	default:
		return token, nil
	}
}
