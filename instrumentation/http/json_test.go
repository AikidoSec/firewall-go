package http

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// json.Decoder reads one value and ignores trailing bytes, so we must
// extract that prefix or attackers bypass inspection by appending garbage.
func TestExtractJSONFromReaderBypassResistance(t *testing.T) {
	t.Run("valid object followed by invalid object", func(t *testing.T) {
		body := `{"name":"Doggo"}{"invalid"}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "Doggo", m["name"])
	})

	t.Run("valid object followed by unclosed object", func(t *testing.T) {
		body := `{"valid":true}{"invalid":{"this is valid":true}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, true, m["valid"])
	})

	t.Run("no valid JSON prefix", func(t *testing.T) {
		assert.Nil(t, ExtractJSONFromReader(strings.NewReader(`garbage{"a":1}`)))
	})
}

func TestExtractJSONFromReaderStreamingBehavior(t *testing.T) {
	t.Run("returns all objects when body contains multiple JSON objects", func(t *testing.T) {
		body := `{"first":true}` + "\n" + `{"second":true}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		gotSlice, ok := got.([]interface{})
		require.True(t, ok, "expected []interface{}, got %T: %v", got, got)
		require.Len(t, gotSlice, 2)
		assert.Equal(t, true, gotSlice[0].(map[string]interface{})["first"])
		assert.Equal(t, true, gotSlice[1].(map[string]interface{})["second"])
	})

	t.Run("returns parsed prefix when valid JSON object is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "{}" + multipartTrailer
		got := ExtractJSONFromReader(strings.NewReader(body))

		assert.Equal(t, map[string]interface{}{}, got)
	})

	t.Run("returns parsed prefix when valid JSON array is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "[]" + multipartTrailer
		got := ExtractJSONFromReader(strings.NewReader(body))

		assert.Equal(t, []interface{}{}, got)
	})
}

func TestExtractJSONFromReader(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		body := `{"key": "value"}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		if got == nil {
			t.Error("expected valid JSON to be parsed, got nil")
		}
	})

	t.Run("bad", func(t *testing.T) {
		body := `not json`
		got := ExtractJSONFromReader(strings.NewReader(body))

		if got != nil {
			t.Errorf("expected invalid JSON to return nil, got %v", got)
		}
	})

	t.Run("duplicate key null bypass retains both values", func(t *testing.T) {
		body := `{"field": "malicious", "field": null}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		assert.Equal(t, map[string]any{"field": []any{"malicious", nil}}, got)
	})

	t.Run("duplicate non-null keys retain both values", func(t *testing.T) {
		body := `{"field": "first", "field": "second"}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		assert.Equal(t, map[string]any{"field": []any{"first", "second"}}, got)
	})

	t.Run("nested duplicate keys retain both values", func(t *testing.T) {
		body := `{"outer": {"inner": "malicious", "inner": null}}`
		got := ExtractJSONFromReader(strings.NewReader(body))

		assert.Equal(t, map[string]any{"outer": map[string]any{"inner": []any{"malicious", nil}}}, got)
	})
}

func TestDuplicateJSONInspection(t *testing.T) {
	tests := []struct {
		name string
		body string
		want any
	}{
		{"three occurrences", `{"field":"first","field":"second","field":"third"}`, map[string]any{"field": []any{"first", "second", "third"}}},
		{"null first", `{"field":null,"field":"attack"}`, map[string]any{"field": []any{nil, "attack"}}},
		{"escaped equivalent names", `{"field":"attack","\u0066ield":"safe"}`, map[string]any{"field": []any{"attack", "safe"}}},
		{"array values remain separate", `{"field":["attack","safe"],"field":["other"],"field":null}`, map[string]any{"field": []any{[]any{"attack", "safe"}, []any{"other"}, nil}}},
		{"object values remain separate", `{"field":{"a":"attack"},"field":{"b":"safe"}}`, map[string]any{"field": []any{map[string]any{"a": "attack"}, map[string]any{"b": "safe"}}}},
		{"duplicates inside arrays", `[{"field":"attack","field":"safe"}]`, []any{map[string]any{"field": []any{"attack", "safe"}}}},
		{"separate objects are not duplicates", `[{"field":"first"},{"field":"second"}]`, []any{map[string]any{"field": "first"}, map[string]any{"field": "second"}}},
		{"later streaming value", `{"ok":true}{"field":"attack","field":null}{"last":42}`, []any{map[string]any{"ok": true}, map[string]any{"field": []any{"attack", nil}}, map[string]any{"last": float64(42)}}},
		{"duplicate prefix followed by garbage", `{"field":"attack","field":null}garbage`, map[string]any{"field": []any{"attack", nil}}},
		{"invalid suffix is not inspected", `{"ok":true}{"field":"attack","field":null`, map[string]any{"ok": true}},
		{"empty containers and scalar types", `{"array":[],"object":{},"number":1.5,"bool":false,"null":null}`, map[string]any{"array": []any{}, "object": map[string]any{}, "number": 1.5, "bool": false, "null": nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractJSONFromReader(strings.NewReader(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJSONInspectionMalformedValues(t *testing.T) {
	for _, body := range []string{
		`{"field":}`, `{"field":1,}`, `{"field":1 "other":2}`,
		`{1:"value"}`, `{"field":1]`, `{"field":"first","field":`,
		`[1,]`, `[1 2]`, `[1}`, `[`, `{`, `"unclosed`, `1e999`,
	} {
		t.Run(body, func(t *testing.T) {
			assert.Nil(t, ExtractJSONFromReader(strings.NewReader(body)))
			assert.Equal(t, map[string]any{"valid": true},
				ExtractJSONFromReader(strings.NewReader(`{"valid":true}`+body)))
		})
	}
}

func TestJSONInspectionNestingLimit(t *testing.T) {
	for _, delimiters := range []struct{ open, close string }{{"[", "]"}, {`{"nested":`, "}"}} {
		body := strings.Repeat(delimiters.open, maxJSONInspectionDepth) + "null" + strings.Repeat(delimiters.close, maxJSONInspectionDepth)
		_, err := readInspectionJSONValue(json.NewDecoder(strings.NewReader(body)), 0)
		require.NoError(t, err)

		body = delimiters.open + body + delimiters.close
		_, err = readInspectionJSONValue(json.NewDecoder(strings.NewReader(body)), 0)
		require.Error(t, err)
		assert.Nil(t, ExtractJSONFromReader(strings.NewReader(body)))
		assert.Equal(t, map[string]any{"valid": true},
			ExtractJSONFromReader(strings.NewReader(`{"valid":true}`+body)))
	}
}

func FuzzJSONInspection(f *testing.F) {
	for _, body := range []string{`{"field":"first","field":null}`, `[{"a":1},true,null]`, `{}`, `{"a":[1,2]}`, `"string"`, `0`} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		ExtractJSONFromReader(strings.NewReader(body))
		// Without duplicates, inspection should match ordinary decoding.
		var want any
		if json.Unmarshal([]byte(body), &want) != nil {
			return
		}
		normalized, err := json.Marshal(want)
		require.NoError(t, err)
		got, err := readInspectionJSONValue(json.NewDecoder(strings.NewReader(string(normalized))), 0)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

func BenchmarkExtractJSONFromReader(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"1KiB", 1 << 10},
		{"5MiB", 5 << 20},
	} {
		b.Run(tc.name, func(b *testing.B) {
			body := `"` + strings.Repeat("a", tc.size-2) + `"`
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))

			for b.Loop() {
				ExtractJSONFromReader(strings.NewReader(body))
			}
		})
	}
}
