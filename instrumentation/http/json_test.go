package http

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// json.Decoder reads one value and ignores trailing bytes, so we must
// extract that prefix or attackers bypass inspection by appending garbage.
func TestTryExtractJSONBypassResistance(t *testing.T) {
	t.Run("valid object followed by invalid object", func(t *testing.T) {
		body := `{"name":"Doggo"}{"invalid"}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "Doggo", m["name"])
	})

	t.Run("valid object followed by unclosed object", func(t *testing.T) {
		body := `{"valid":true}{"invalid":{"this is valid":true}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, true, m["valid"])
	})

	t.Run("no valid JSON prefix", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/test", strings.NewReader(`garbage{"a":1}`))

		assert.Nil(t, tryExtractJSON(r))
	})

	t.Run("body is restored after partial extraction", func(t *testing.T) {
		body := `{"name":"Doggo"}{"invalid"}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		_ = tryExtractJSON(r)

		restored, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(restored))
	})
}

func TestTryExtractJSONStreamingBehavior(t *testing.T) {
	t.Run("returns all objects when body contains multiple JSON objects", func(t *testing.T) {
		body := `{"first":true}` + "\n" + `{"second":true}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		gotSlice, ok := got.([]interface{})
		require.True(t, ok, "expected []interface{}, got %T: %v", got, got)
		require.Len(t, gotSlice, 2)
		assert.Equal(t, true, gotSlice[0].(map[string]interface{})["first"])
		assert.Equal(t, true, gotSlice[1].(map[string]interface{})["second"])

		restoredBody, _ := io.ReadAll(r.Body)
		assert.Equal(t, body, string(restoredBody))
	})

	t.Run("returns parsed prefix when valid JSON object is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "{}" + multipartTrailer
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Equal(t, map[string]interface{}{}, got)
	})

	t.Run("returns parsed prefix when valid JSON array is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "[]" + multipartTrailer
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Equal(t, []interface{}{}, got)
	})
}

func TestTryExtractJSON(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		body := `{"key": "value"}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		if got == nil {
			t.Error("expected valid JSON to be parsed, got nil")
		}

		// Verify body is restored
		restoredBody, _ := io.ReadAll(r.Body)
		if string(restoredBody) != body {
			t.Errorf("body not restored: got %q, want %q", string(restoredBody), body)
		}
	})

	t.Run("bad", func(t *testing.T) {
		body := `not json`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		if got != nil {
			t.Errorf("expected invalid JSON to return nil, got %v", got)
		}

		// Verify body is still restored even on failure
		restoredBody, _ := io.ReadAll(r.Body)
		if string(restoredBody) != body {
			t.Errorf("body not restored: got %q, want %q", string(restoredBody), body)
		}
	})

	t.Run("duplicate key null bypass retains both values", func(t *testing.T) {
		body := `{"field": "malicious", "field": null}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Equal(t, map[string]any{"field": []any{"malicious", nil}}, got)

		restoredBody, _ := io.ReadAll(r.Body)
		assert.Equal(t, body, string(restoredBody))
	})

	t.Run("duplicate non-null keys retain both values", func(t *testing.T) {
		body := `{"field": "first", "field": "second"}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Equal(t, map[string]any{"field": []any{"first", "second"}}, got)
	})

	t.Run("nested duplicate keys retain both values", func(t *testing.T) {
		body := `{"outer": {"inner": "malicious", "inner": null}}`
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

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
			r := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			got := tryExtractJSON(r)
			assert.Equal(t, tt.want, got)
			restored, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.body, string(restored))
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

func BenchmarkSmallBody(b *testing.B) {
	body := generateString(1 * 1024) // 1KB
	for b.Loop() {
		r := httptest.NewRequest("GET", "/route", strings.NewReader(body))
		tryExtractJSON(r)
	}
}

func BenchmarkLargeBody(b *testing.B) {
	body := generateString(5 * 1024 * 1024) // 5MB
	for b.Loop() {
		r := httptest.NewRequest("GET", "/route", strings.NewReader(body))
		tryExtractJSON(r)
	}
}

func generateString(targetSize int) string {
	var b strings.Builder
	b.Grow(targetSize) // Pre-allocate memory for efficiency

	// Start with "{"
	b.WriteString("{")

	// Fill the rest with content to reach 5MB
	chunk := strings.Repeat("a", 1024) // 1KB chunks
	for b.Len() < targetSize {
		remaining := targetSize - b.Len()
		if remaining < len(chunk) {
			b.WriteString(chunk[:remaining])
		} else {
			b.WriteString(chunk)
		}
	}

	return b.String()
}
