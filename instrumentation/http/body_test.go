package http

import (
	"bytes"
	"errors"
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

func TestTryExtractBodyPreservesClose(t *testing.T) {
	closeErr := errors.New("close failed")

	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		closeErr    error
	}{
		{"JSON", "application/json", `{"key":"value"}`, nil},
		{"form", "application/x-www-form-urlencoded", "key=value", nil},
		{"invalid body", "application/octet-stream", "not json", nil},
		{"close error", "application/json", `{"key":"value"}`, closeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &closeTrackingBody{Reader: strings.NewReader(tc.body), err: tc.closeErr}
			req := httptest.NewRequest(http.MethodPost, "/test", body)
			req.Header.Set("Content-Type", tc.contentType)

			TryExtractBody(req)

			assert.Zero(t, body.closes)
			restored, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(restored))

			assert.Equal(t, tc.closeErr, req.Body.Close())
			assert.Equal(t, 1, body.closes)
		})
	}
}

type closeTrackingBody struct {
	io.Reader
	closes int
	err    error
}

func (b *closeTrackingBody) Close() error {
	b.closes++
	return b.err
}

func TestTryExtractFormBody(t *testing.T) {
	t.Run("urlencoded form", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "alice")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result := tryExtractFormBody(req)

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

		result := tryExtractFormBody(req)

		assert.NotNil(t, result)
		assert.Equal(t, "value1", result.Get("field1"))
	})

	t.Run("parse error returns nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("some data"))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		result := tryExtractFormBody(req)

		assert.Nil(t, result)
	})
}

func TestTryExtractFormBody_EmptyData(t *testing.T) {
	t.Run("nil body with populated PostForm returns PostForm", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", http.NoBody)
		req.PostForm = url.Values{"username": []string{"alice"}}

		result := tryExtractFormBody(req)

		assert.NotNil(t, result)
		assert.Equal(t, "alice", result.Get("username"))
	})

	t.Run("nil body with nil PostForm returns nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", http.NoBody)

		result := tryExtractFormBody(req)

		assert.Nil(t, result)
	})
}

func TestTryExtractBody(t *testing.T) {
	t.Run("extracts JSON", func(t *testing.T) {
		jsonBody := `{"username":"alice"}`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		result := TryExtractBody(req)

		assert.NotNil(t, result)
	})

	t.Run("extracts form when JSON fails", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "bob")

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result := TryExtractBody(req)

		assert.NotNil(t, result)
		formValues, ok := result.(url.Values)
		require.True(t, ok)
		assert.Equal(t, "bob", formValues.Get("username"))
	})

	t.Run("returns nil when both fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("some data"))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		result := TryExtractBody(req)

		assert.Nil(t, result)
	})

	t.Run("returns nil when no body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", http.NoBody)

		result := TryExtractBody(req)

		assert.Nil(t, result)
	})

	t.Run("preserves duplicate JSON values for inspection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"field":"malicious","field":null}`))
		req.Header.Set("Content-Type", "application/json")

		result := TryExtractBody(req)

		assert.Equal(t, map[string]any{"field": []any{"malicious", nil}}, result)
	})

	t.Run("duplicate JSON prefix does not suppress form inspection", func(t *testing.T) {
		body := `{"field":"attack","field":null}=form-value`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		result := TryExtractBody(req)
		assert.Equal(t, []any{
			map[string]any{"field": []any{"attack", nil}},
			url.Values{`{"field":"attack","field":null}`: {"form-value"}},
		}, result)
		restored, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(restored))
	})
}

func TestTryExtractBodyBypassVectors(t *testing.T) {
	t.Run("empty JSON object prefix does not suppress multipart field extraction", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("name", "injected")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("{}\n"+body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		result := TryExtractBody(req)

		combined, ok := result.([]any)
		require.True(t, ok, "got %T: %v", result, result)
		require.Len(t, combined, 2)
		assert.Equal(t, map[string]interface{}{}, combined[0])
		formValues, ok := combined[1].(url.Values)
		require.True(t, ok)
		assert.Equal(t, "injected", formValues.Get("name"))
	})

	t.Run("non-empty JSON object prefix does not suppress multipart field extraction", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("name", "injected")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"key":"val"}`+"\n"+body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		result := TryExtractBody(req)

		combined, ok := result.([]any)
		require.True(t, ok, "got %T: %v", result, result)
		require.Len(t, combined, 2)
		jsonMap, ok := combined[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "val", jsonMap["key"])
		formValues, ok := combined[1].(url.Values)
		require.True(t, ok)
		assert.Equal(t, "injected", formValues.Get("name"))
	})

	t.Run("empty JSON array prefix does not suppress multipart field extraction", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("name", "injected")
		writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("[]\n"+body.String()))
		req.Header.Set("Content-Type", writer.FormDataContentType())

		result := TryExtractBody(req)

		combined, ok := result.([]any)
		require.True(t, ok, "got %T: %v", result, result)
		require.Len(t, combined, 2)
		assert.Equal(t, []interface{}{}, combined[0])
		formValues, ok := combined[1].(url.Values)
		require.True(t, ok)
		assert.Equal(t, "injected", formValues.Get("name"))
	})

	t.Run("JSON body is scanned even when Content-Type is multipart", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"name":"injected"}`))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=----boundary")

		result := TryExtractBody(req)

		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok, "expected map, got %T: %v", result, result)
		assert.Equal(t, "injected", resultMap["name"])
	})

	t.Run("NDJSON body returns all objects for inspection", func(t *testing.T) {
		body := `{"payload":"safe"}` + "\n" + `{"payload":"danger"}`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		result := TryExtractBody(req)

		resultSlice, ok := result.([]interface{})
		require.True(t, ok, "expected []interface{} for NDJSON body, got %T: %v", result, result)
		require.Len(t, resultSlice, 2)

		second, ok := resultSlice[1].(map[string]interface{})
		require.True(t, ok, "expected second element to be a map")
		assert.Equal(t, "danger", second["payload"])
	})
}

func TestBodyStillReadableAfterExtraction(t *testing.T) {
	t.Run("body readable after form extraction", func(t *testing.T) {
		formData := url.Values{}
		formData.Set("username", "alice")
		originalBody := formData.Encode()

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		TryExtractBody(req)

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

		TryExtractBody(req)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, bodyBytes)
	})

	t.Run("body readable after parse error", func(t *testing.T) {
		originalBody := "some data"
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "multipart/form-data") // Missing boundary

		TryExtractBody(req)

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

		TryExtractBody(req)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})

	t.Run("body readable after TryExtractBody with JSON", func(t *testing.T) {
		originalBody := `{"username":"alice","email":"test@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(originalBody))
		req.Header.Set("Content-Type", "application/json")

		TryExtractBody(req)

		bodyBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, originalBody, string(bodyBytes))
	})
}

func TestTryExtractBodyPreservesFormState(t *testing.T) {
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	require.NoError(t, writer.WriteField("username", "mallory"))
	require.NoError(t, writer.Close())

	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		preparsed   bool
	}{
		{name: "urlencoded", contentType: "application/x-www-form-urlencoded", body: "username=mallory"},
		{name: "multipart", contentType: writer.FormDataContentType(), body: multipartBody.String()},
		{name: "existing form state", contentType: writer.FormDataContentType(), body: multipartBody.String(), preparsed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.preparsed {
				req.Form = url.Values{"username": {"normalized"}, "query": {"value"}}
				req.PostForm = url.Values{"username": {"normalized"}}
				req.MultipartForm = &multipart.Form{Value: url.Values{"username": {"normalized"}}}
			}
			originalForm := req.Form
			originalPostForm := req.PostForm
			originalMultipartForm := req.MultipartForm

			result := TryExtractBody(req)

			assert.Equal(t, url.Values{"username": {"mallory"}}, result)
			assert.Equal(t, originalForm, req.Form)
			assert.Equal(t, originalPostForm, req.PostForm)
			assert.Same(t, originalMultipartForm, req.MultipartForm)
			restored, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(restored))
		})
	}
}

func TestTryExtractBodyRetainsConsumedForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		body io.ReadCloser
	}{
		{name: "consumed body", body: io.NopCloser(strings.NewReader(""))},
		{name: "nil body"},
		{name: "NoBody", body: http.NoBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/signup?query=value", nil)
			req.Body = tc.body
			req.Form = url.Values{"username": {"alice"}, "query": {"value"}}
			req.PostForm = url.Values{"username": {"alice", "bob"}}
			req.MultipartForm = &multipart.Form{Value: map[string][]string{"username": {"alice", "bob"}}}
			originalMultipartForm := req.MultipartForm

			result, ok := TryExtractBody(req).(url.Values)
			require.True(t, ok)
			assert.Equal(t, req.PostForm, result)
			assert.NotContains(t, result, "query", "query parameters are not body fields")

			result["username"][0] = "changed"
			result.Set("extra", "value")
			assert.Equal(t, url.Values{"username": {"alice", "bob"}}, req.PostForm)
			assert.Equal(t, "alice", req.MultipartForm.Value["username"][0])
			assert.Same(t, originalMultipartForm, req.MultipartForm)
		})
	}
}

func TestTryExtractBodyPreservesDownstreamFormMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inspect bool
	}{
		{name: "without inspection", inspect: false},
		{name: "with inspection", inspect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newRequest := func(t *testing.T, body string) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tc.inspect {
					result := TryExtractBody(req)
					require.Equal(t, mustParseQuery(t, body), result)
				}
				assert.Nil(t, req.Form, "inspection must not populate the application's form cache")
				assert.Nil(t, req.PostForm, "inspection must not populate the application's body form cache")
				assert.Nil(t, req.MultipartForm)
				return req
			}

			t.Run("body filtering", func(t *testing.T) {
				req := newRequest(t, "username=mallory&role=admin&is_admin=1")

				// Application middleware removes server-controlled fields from the body.
				raw, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				form := mustParseQuery(t, string(raw))
				form.Del("role")
				form.Del("is_admin")
				clean := form.Encode()
				req.Body = io.NopCloser(strings.NewReader(clean))
				req.ContentLength = int64(len(clean))

				// The handler should parse the filtered body, not inspection's cached form.
				require.NoError(t, req.ParseForm())
				assert.Equal(t, "mallory", req.PostForm.Get("username"))
				assert.Empty(t, req.PostForm.Get("role"))
				assert.Empty(t, req.PostForm.Get("is_admin"))
			})

			t.Run("body size limit", func(t *testing.T) {
				const limit = 1024
				req := newRequest(t, "username="+strings.Repeat("a", 2*limit))

				// Application middleware enforces its limit when the handler reads the body.
				req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, limit)
				err := req.ParseForm()
				var limitErr *http.MaxBytesError
				require.ErrorAs(t, err, &limitErr, "form parsing must read through the application's body limiter")
				assert.Equal(t, int64(limit), limitErr.Limit)
			})
		})
	}
}

func mustParseQuery(t *testing.T, body string) url.Values {
	t.Helper()
	form, err := url.ParseQuery(body)
	require.NoError(t, err)
	return form
}

func TestTryExtractBodyRestoresBody(t *testing.T) {
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	require.NoError(t, writer.WriteField("field", "value"))
	require.NoError(t, writer.Close())

	for _, tc := range []struct {
		name        string
		contentType string
		body        string
	}{
		{"binary", "application/octet-stream", strings.Repeat("\x00", 64<<10)},
		{"invalid JSON", "application/json", "not json"},
		{"partial JSON", "application/json", `{"name":"Doggo"}{"invalid"}`},
		{"streaming JSON", "application/json", "{\"first\":true}\n{\"second\":true}"},
		{"duplicate JSON keys", "application/json", `{"field":"malicious","field":null}`},
		{"invalid multipart", "multipart/form-data", "not a form"},
		{"multipart", writer.FormDataContentType(), multipartBody.String()},
		{"JSON and multipart", writer.FormDataContentType(), "{}\n" + multipartBody.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)

			TryExtractBody(req)

			restored, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(restored))
		})
	}
}
