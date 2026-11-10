package http

import (
	"encoding/json"
	"io"
)

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
