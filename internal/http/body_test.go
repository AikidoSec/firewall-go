package http

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockParser implements MultipartFormParser for testing
type mockParser struct {
	req *http.Request
}

func (m *mockParser) MultipartForm() (*multipart.Form, error) {
	err := m.req.ParseMultipartForm(32 << 20)
	if err != nil {
		return nil, err
	}
	return m.req.MultipartForm, nil
}

func TestTryExtractFormBody(t *testing.T) {
	t.Run("urlencoded form", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "alice")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		parser := &mockParser{req: req}
		result := tryExtractFormBody(req, parser)

		assert.NotNil(t, result)
		assert.Equal(t, "alice", result.Get("username"))
	})

	t.Run("multipart form", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("field1", "value1")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/test", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		parser := &mockParser{req: req}
		result := tryExtractFormBody(req, parser)

		assert.NotNil(t, result)
		assert.Equal(t, "value1", result.Get("field1"))
	})

	t.Run("parse error returns nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("some data"))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		parser := &mockParser{req: req}
		result := tryExtractFormBody(req, parser)

		assert.Nil(t, result)
	})
}

func TestTryExtractBody(t *testing.T) {
	t.Run("extracts JSON", func(t *testing.T) {
		jsonBody := `{"username":"alice"}`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		parser := &mockParser{req: req}
		result := TryExtractBody(req, parser)

		assert.NotNil(t, result)
	})

	t.Run("extracts form when JSON fails", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "bob")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		parser := &mockParser{req: req}
		result := TryExtractBody(req, parser)

		assert.NotNil(t, result)
		formValues, ok := result.(url.Values)
		require.True(t, ok)
		assert.Equal(t, "bob", formValues.Get("username"))
	})

	t.Run("returns nil when both fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("some data"))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		parser := &mockParser{req: req}
		result := TryExtractBody(req, parser)

		assert.Nil(t, result)
	})
}

func TestBodyStillReadableAfterExtraction(t *testing.T) {
	t.Run("body readable after form extraction", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "alice")
		originalBody := formData.Encode()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		parser := &mockParser{req: req}
		tryExtractFormBody(req, parser)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})

	t.Run("body readable after multipart extraction", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("field1", "value1")
		writer.Close()

		originalBody := body.Bytes()
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(originalBody))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		parser := &mockParser{req: req}
		tryExtractFormBody(req, parser)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, bodyBytes)
	})

	t.Run("body readable after parse error", func(t *testing.T) {
		originalBody := "some data"
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		parser := &mockParser{req: req}
		tryExtractFormBody(req, parser)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})

	t.Run("body readable after TryExtractBody with form", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "bob")
		originalBody := formData.Encode()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		parser := &mockParser{req: req}
		TryExtractBody(req, parser)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})

	t.Run("body readable after TryExtractBody with JSON", func(t *testing.T) {
		originalBody := `{"username":"alice","email":"test@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "application/json")

		parser := &mockParser{req: req}
		TryExtractBody(req, parser)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})
}
