package http

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAIResponse(t *testing.T) {
	cases := []struct {
		path, body, model string
		input, output     int
	}{
		{"/proxy/v1/chat/completions", `{"model":"gpt-4o","usage":{"prompt_tokens":100,"completion_tokens":20}}`, "gpt-4o", 100, 20},
		{"/openai/deployments/gpt/chat/completions?api-version=secret", `{"model":"gpt-4o"}`, "gpt-4o", 0, 0},
		{"/proxy/v1/responses", `{"model":"gpt-4o","usage":{"input_tokens":100,"output_tokens":20}}`, "gpt-4o", 100, 20},
		{"/proxy/v1/messages", `{"model":"claude","usage":{"input_tokens":1,"output_tokens":2}}`, "claude", 1, 2},
		{"/v1/projects/p/locations/l/publishers/anthropic/models/claude:rawPredict", `{"model":"claude","usage":{"input_tokens":1,"output_tokens":2}}`, "claude", 1, 2},
		{"/v1beta/models/gemini:generateContent?key=secret", `{"modelVersion":"gemini-2.5","usageMetadata":{"promptTokenCount":98,"toolUsePromptTokenCount":2,"candidatesTokenCount":15,"thoughtsTokenCount":5}}`, "gemini-2.5", 100, 20},
		{"/v1/projects/p/locations/l/publishers/google/models/gemini:generateContent", `{}`, "gemini", 0, 0},
		{"/model/us.anthropic.claude-v1%3A0/converse", `{"usage":{"inputTokens":1,"outputTokens":2}}`, "us.anthropic.claude-v1:0", 1, 2},
		{"/model/anthropic.claude-v1%3A0/invoke", `{"model":"claude","usage":{"input_tokens":1,"output_tokens":2}}`, "anthropic.claude-v1:0", 1, 2},
		{"/model/arn%3Aaws%3Abedrock%3Amodel/converse", `{"model":"claude"}`, "claude", 0, 0},
		{"/v1/responses", `{"model":"gpt","usage":{"input_tokens":-1,"output_tokens":"20"}}`, "gpt", 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			u, err := url.Parse("https://user:password@gateway.internal:8443" + tc.path + "#secret")
			require.NoError(t, err)

			call, ok := parseAIResponse(u, []byte(tc.body))
			require.True(t, ok)

			assert.Equal(t, aiCall{"https://gateway.internal:8443", tc.model, tc.input, tc.output}, call)
		})
	}
}

func TestParseAIResponseIgnoresInvalidResponses(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `"text"`, `{`, `{}`, `{"model":123}`, `{"model":""}`, `{"error":{"message":"failed"}}`} {
		u, _ := url.Parse("https://api.openai.com/v1/responses")
		_, ok := parseAIResponse(u, []byte(body))

		assert.False(t, ok, body)
	}

	for _, path := range []string{"/v1/embeddings", "/models/gemini:streamGenerateContent", "/v1/messages/extra", "/other:rawPredict", "/converse"} {
		assert.False(t, isAIRequestPath(path), path)

		u, _ := url.Parse("https://example.com" + path)
		_, ok := parseAIResponse(u, []byte(`{"model":"gpt"}`))
		assert.False(t, ok, path)
	}
}

func TestTokenCount(t *testing.T) {
	for _, value := range []string{`-1`, `1.5`, `"20"`, `null`, `true`, `9223372036854775808`, `1e100`, `{}`} {
		assert.Zero(t, tokenCount([]byte(value)), value)
	}

	assert.Equal(t, 20, tokenCount([]byte(`20`)))
}
