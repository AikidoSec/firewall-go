package http

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

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
