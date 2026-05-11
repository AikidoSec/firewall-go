package http

import (
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
