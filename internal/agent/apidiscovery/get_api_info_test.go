package apidiscovery

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsObject(t *testing.T) {
	t.Run("Test isObject", func(t *testing.T) {
		assert.Equal(t, false, isObject(""))
		assert.Equal(t, false, isObject([]string{"1"}))
		assert.Equal(t, false, isObject(nil))

		assert.Equal(t, true, isObject(map[string]any{"1": "2"}))
		assert.Equal(t, true, isObject(map[string]string{"1": "2"}))
		assert.Equal(t, true, isObject(map[string]int{"1": 500}))
		assert.Equal(t, true, isObject(map[string][]string{"1": {"2"}}))
		assert.Equal(t, true, isObject(map[string][]any{"1": {"2"}}))
	})
}

func TestGetAPIInfo(t *testing.T) {
	t.Run("returns nil when API schema collection is disabled", func(t *testing.T) {
		config.CollectAPISchema = false
		t.Cleanup(func() { config.CollectAPISchema = true })

		ctx := &request.Context{
			Body:    map[string]any{"key": "value"},
			Headers: map[string][]string{"content-type": {"application/json"}},
		}

		result := GetAPIInfo(ctx)
		assert.Nil(t, result)
	})

	t.Run("returns nil when body and query and auth are all empty", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{}

		result := GetAPIInfo(ctx)
		assert.Nil(t, result)
	})

	t.Run("returns nil when body type is undefined", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Body:    map[string]any{"key": "value"},
			Headers: map[string][]string{}, // no content-type
		}

		result := GetAPIInfo(ctx)
		assert.Nil(t, result)
	})

	t.Run("returns body schema for JSON body", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Body:    map[string]any{"name": "test", "age": 25},
			Headers: map[string][]string{"content-type": {"application/json"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		require.NotNil(t, result.Body)
		assert.Equal(t, "json", result.Body.Type)
		require.NotNil(t, result.Body.Schema)
	})

	t.Run("returns query schema when query params present", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Query: map[string][]string{"search": {"test"}, "page": {"1"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		require.NotNil(t, result.Query)
	})

	t.Run("returns auth info when authorization header present", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Headers: map[string][]string{"authorization": {"Bearer token123"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		require.NotNil(t, result.Auth)
		assert.Equal(t, "http", result.Auth[0].Type)
		assert.Equal(t, "bearer", result.Auth[0].Scheme)
	})

	t.Run("returns auth info from cookies", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Headers: map[string][]string{},
			Cookies: map[string]string{"session": "abc123"},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		require.NotNil(t, result.Auth)
		assert.Equal(t, "apiKey", result.Auth[0].Type)
		assert.Equal(t, "cookie", result.Auth[0].In)
	})

	t.Run("returns combined body, query, and auth", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Body:  map[string]any{"data": "value"},
			Query: map[string][]string{"q": {"search"}},
			Headers: map[string][]string{
				"content-type":  {"application/json"},
				"authorization": {"Bearer tok"},
			},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		assert.NotNil(t, result.Body)
		assert.NotNil(t, result.Query)
		assert.NotNil(t, result.Auth)
	})

	t.Run("ignores non-object body", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Body:    "just a string",
			Headers: map[string][]string{"content-type": {"application/json"}},
			Query:   map[string][]string{"q": {"test"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		assert.Nil(t, result.Body)
		assert.NotNil(t, result.Query)
	})

	t.Run("ignores empty query map", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Query:   map[string][]string{},
			Headers: map[string][]string{"authorization": {"Bearer tok"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		assert.Nil(t, result.Query)
		assert.NotNil(t, result.Auth)
	})

	t.Run("returns body schema for form-urlencoded body", func(t *testing.T) {
		config.CollectAPISchema = true

		ctx := &request.Context{
			Body:    map[string]any{"field": "val"},
			Headers: map[string][]string{"content-type": {"application/x-www-form-urlencoded"}},
		}

		result := GetAPIInfo(ctx)
		require.NotNil(t, result)
		require.NotNil(t, result.Body)
		assert.Equal(t, "form-urlencoded", result.Body.Type)
	})
}
