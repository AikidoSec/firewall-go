//go:build !integration

package fiber_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	zenfiber "github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v3"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extractedBody runs a POST request through the middleware and returns the
// Body that ended up in the request context.
func extractedBody(t *testing.T, body io.Reader, contentType string) any {
	t.Helper()

	app := newTestApp()
	app.Use(zenfiber.GetMiddleware())

	var captured any
	app.Post("/route", func(c fiber.Ctx) error {
		captured = request.GetContext(c.Context()).Body
		return c.SendString("ok")
	})

	r := httptest.NewRequest("POST", "/route", body)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}

	resp, err := app.Test(r)
	require.NoError(t, err)
	defer resp.Body.Close()

	return captured
}

func multipartBody(t *testing.T, fields map[string]string) (io.Reader, string) {
	t.Helper()

	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)
	for k, v := range fields {
		require.NoError(t, writer.WriteField(k, v))
	}
	require.NoError(t, writer.Close())

	return buf, writer.FormDataContentType()
}

func TestExtractBodyJSON(t *testing.T) {
	t.Run("valid object", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`{"username":"alice"}`), "application/json")

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "alice", m["username"])
	})

	t.Run("invalid JSON returns nil", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`not json`), "application/json")
		assert.Nil(t, got)
	})

	t.Run("no body returns nil", func(t *testing.T) {
		got := extractedBody(t, http.NoBody, "")
		assert.Nil(t, got)
	})
}

// json.Decoder reads one value and ignores trailing bytes, so we must
// extract that prefix or attackers bypass inspection by appending garbage.
func TestExtractBodyJSONBypassResistance(t *testing.T) {
	t.Run("valid object followed by invalid object", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`{"name":"Doggo"}{"invalid"}`), "")

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "Doggo", m["name"])
	})

	t.Run("valid object followed by unclosed object", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`{"valid":true}{"invalid":{"this is valid":true}`), "")

		m, ok := got.(map[string]interface{})
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, true, m["valid"])
	})

	t.Run("no valid JSON prefix", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`garbage{"a":1}`), "")
		assert.Nil(t, got)
	})
}

func TestExtractBodyNDJSON(t *testing.T) {
	t.Run("returns all objects when body contains multiple JSON objects", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader(`{"first":true}`+"\n"+`{"second":true}`), "application/json")

		gotSlice, ok := got.([]interface{})
		require.True(t, ok, "expected []interface{}, got %T: %v", got, got)
		require.Len(t, gotSlice, 2)
		assert.Equal(t, true, gotSlice[0].(map[string]interface{})["first"])
		assert.Equal(t, true, gotSlice[1].(map[string]interface{})["second"])
	})

	t.Run("returns parsed prefix when valid JSON object is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		got := extractedBody(t, strings.NewReader("{}"+multipartTrailer), "")

		assert.Equal(t, map[string]interface{}{}, got)
	})

	t.Run("returns parsed prefix when valid JSON array is followed by non-JSON content", func(t *testing.T) {
		multipartTrailer := "\n------boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n------boundary--"
		got := extractedBody(t, strings.NewReader("[]"+multipartTrailer), "")

		assert.Equal(t, []interface{}{}, got)
	})
}

func TestExtractBodyForm(t *testing.T) {
	t.Run("urlencoded form", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader("username=alice&password=secret"), "application/x-www-form-urlencoded")

		formValues, ok := got.(url.Values)
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "alice", formValues.Get("username"))
	})

	t.Run("multipart form", func(t *testing.T) {
		body, contentType := multipartBody(t, map[string]string{"field1": "value1"})
		got := extractedBody(t, body, contentType)

		formValues, ok := got.(url.Values)
		require.True(t, ok, "got %T: %v", got, got)
		assert.Equal(t, "value1", formValues.Get("field1"))
	})

	t.Run("multipart with missing boundary returns nil", func(t *testing.T) {
		got := extractedBody(t, strings.NewReader("some data"), "multipart/form-data")
		assert.Nil(t, got)
	})
}
