package http

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	t.Run("returns nil when valid JSON is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "{}" + multipartTrailer
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Nil(t, got)
	})

	t.Run("returns nil when valid JSON array is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		body := "[]" + multipartTrailer
		r := httptest.NewRequest("POST", "/test", strings.NewReader(body))

		got := tryExtractJSON(r)

		assert.Nil(t, got)
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
