package ai

import (
	"fmt"
	"math"
	"net/url"
	"strings"
	"testing"
	"unsafe"

	"github.com/AikidoSec/firewall-go/internal/ai/providers"
	"github.com/stretchr/testify/require"
)

func parseResponseForURL(rawURL, body string) *providers.Usage {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	kind, usage := ClassifyURL(u)
	return ParseResponse(kind, usage, []byte(body))
}

func TestParseResponse(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
		kind             ResponseKind
		want             providers.Usage
	}{
		{"OpenAI chat", "/custom/chat/completions?key=secret", `{"model":"gpt","usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":3,"cache_write_tokens":2}}}`, openAIChat, providers.Usage{Model: "gpt", Input: 10, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"OpenAI responses", "/v1/responses", `{"model":"gpt","usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":3,"cache_write_tokens":2}}}`, openAIResponses, providers.Usage{Model: "gpt", Input: 10, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"Anthropic", "/v1/messages", `{"model":"claude","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}`, anthropic, providers.Usage{Model: "claude", Input: 15, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"Anthropic cached input", "/v1/messages", `{"model":"claude","usage":{"input_tokens":0,"output_tokens":5,"cache_read_input_tokens":100}}`, anthropic, providers.Usage{Model: "claude", Input: 100, Output: 5, CacheRead: 100}},
		{"Vertex Anthropic", "/publishers/anthropic/models/claude:rawPredict", `{"model":"claude","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}`, anthropic, providers.Usage{Model: "claude", Input: 15, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"Gemini", "/v1beta/models/gemini:generateContent", `{"modelVersion":"gemini-2","usageMetadata":{"promptTokenCount":8,"toolUsePromptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":2,"cachedContentTokenCount":4}}`, gemini, providers.Usage{Model: "gemini-2", Input: 10, Output: 5, CacheRead: 4}},
		{"Gemini model fallback", "/models/gemini:generateContent", `{"usageMetadata":{"promptTokenCount":10}}`, gemini, providers.Usage{Model: "gemini", Input: 10}},
		{"Gemini encoded model fallback", "/models/gemini%2D2%2E5:generateContent", `{"usageMetadata":{"promptTokenCount":10}}`, gemini, providers.Usage{Model: "gemini-2.5", Input: 10}},
		{"Gemini interactions", "/v1beta/interactions", `{"model":"gemini-2.5-flash","usage":{"total_input_tokens":8,"total_tool_use_tokens":2,"total_output_tokens":3,"total_thought_tokens":2,"total_cached_tokens":4}}`, geminiInteraction, providers.Usage{Model: "gemini-2.5-flash", Input: 10, Output: 5, CacheRead: 4}},
		{"Gemini interactions proxy", "/proxy/v1/interactions?key=secret", `{"model":"gemini","usage":{}}`, geminiInteraction, providers.Usage{Model: "gemini"}},
		{"Bedrock Converse", "/model/anthropic.claude/converse", `{"usage":{"inputTokens":10,"outputTokens":5,"cacheReadInputTokens":3,"cacheWriteInputTokens":2}}`, bedrockConverse, providers.Usage{Model: "anthropic.claude", Input: 15, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"Bedrock Invoke", "/model/anthropic.claude/invoke", `{"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}`, bedrockInvoke, providers.Usage{Model: "anthropic.claude", Input: 15, Output: 5, CacheRead: 3, CacheWrite: 2}},
		{"Bedrock encoded model", "/model/anthropic%2Eclaude/invoke", `{"usage":{"input_tokens":10}}`, bedrockInvoke, providers.Usage{Model: "anthropic.claude", Input: 10}},
		{"Bedrock model decoded once", "/model/anthropic%252Eclaude/invoke", `{"usage":{"input_tokens":10}}`, bedrockInvoke, providers.Usage{Model: "anthropic%2Eclaude", Input: 10}},
		{"Bedrock ARN response model", "/model/arn%3Aaws%3Abedrock%3Aregion%3Aaccount%3Amodel%2Fname/invoke", `{"model":"claude","usage":{"input_tokens":10}}`, bedrockInvoke, providers.Usage{Model: "claude", Input: 10}},
		{"Bedrock Converse ARN fallback", "/model/arn%3Aaws%3Abedrock%3Amodel%2Fname/converse", `{"usage":{"inputTokens":10}}`, bedrockConverse, providers.Usage{Model: "arn:aws:bedrock:model/name", Input: 10}},
		{"Bedrock Invoke ARN fallback", "/model/arn%3Aaws%3Abedrock%3Amodel%2Fname/invoke", `{"usage":{"input_tokens":10}}`, bedrockInvoke, providers.Usage{Model: "arn:aws:bedrock:model/name", Input: 10}},
		{"nesting characters in text", "/v1/responses", `{"model":"gpt","usage":{},"text":"[[[\"\\}}"}`, openAIResponses, providers.Usage{Model: "gpt"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse("https://user:password@GATEWAY.test:443" + tt.path)
			require.NoError(t, err)
			kind, usage := ClassifyURL(u)
			require.Equal(t, tt.kind, kind)
			require.True(t, IsRequestPath(u.EscapedPath()))
			parsed := ParseResponse(kind, usage, []byte(tt.body))
			require.Same(t, usage, parsed)
			tt.want.Provider = "https://gateway.test"
			require.Equal(t, &tt.want, parsed)
		})
	}
}

func TestParseResponseRejectsInvalidResponses(t *testing.T) {
	for name, body := range map[string]string{
		"invalid JSON": "{invalid", "trailing JSON": `{"model":"gpt"}{}`, "array": `[]`, "null": `null`,
		"streaming":     "data: {\"model\":\"gpt\"}\n\ndata: [DONE]\n\n",
		"missing model": `{"usage":{}}`, "non-string model": `{"model":123,"usage":{}}`,
		"missing usage": `{"model":"gpt"}`, "null usage": `{"model":"gpt","usage":null}`,
		"long model":    `{"model":"` + strings.Repeat("x", 257) + `","usage":{}}`,
		"oversized":     `{"model":"gpt","usage":{},"text":"` + strings.Repeat("x", maxBodyBytes) + `"}`,
		"deeply nested": `{"model":"gpt","usage":{},"data":` + strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001) + "}",
	} {
		t.Run(name, func(t *testing.T) {
			require.Nil(t, parseResponseForURL("https://gateway.test/v1/responses", body))
		})
	}
}

func TestParseResponseRejectsMalformedUsage(t *testing.T) {
	for _, tt := range []struct{ path, body string }{
		{"/v1/chat/completions", `{"model":"gpt","usage":{"prompt_tokens_details":[]}}`},
		{"/v1/responses", `{"model":"gpt","usage":{"input_tokens":"10"}}`},
		{"/v1/responses", `{"model":"gpt","usage":{"input_tokens_details":{"cached_tokens":-1}}}`},
		{"/v1/responses", `{"model":"gpt","usage":{"input_tokens_details":{"cache_write_tokens":-1}}}`},
		{"/v1/messages", `{"model":"claude","usage":{"cache_read_input_tokens":"3"}}`},
		{"/model/claude/converse", `{"usage":{"outputTokens":false}}`},
		{"/model/claude/invoke", `{"usage":[]}`},
		{"/model/claude/invoke", `{"model":"claude"}`},
		{"/model/claude/invoke", `{"usage":{"prompt_tokens":10}}`},
		{"/models/gemini:generateContent", `{"usageMetadata":{"thoughtsTokenCount":"5"}}`},
		{"/model/claude/converse", `null`},
		{"/models/gemini:generateContent", `null`},
		{"/models/gemini:generateContent", `{}`},
		{"/v1beta/interactions", `{"usage":{"total_input_tokens":10}}`},
		{"/v1beta/interactions", `{"model":"gemini"}`},
		{"/v1beta/interactions", `{"model":"gemini","usage":null}`},
		{"/v1beta/interactions", `{"model":"gemini","usage":{"total_input_tokens":"10"}}`},
		{"/v1beta/interactions", `{"model":"gemini","usage":{"total_cached_tokens":true}}`},
		{"/v1beta/interactions", `null`},
	} {
		t.Run(tt.path+tt.body, func(t *testing.T) {
			require.Nil(t, parseResponseForURL("https://gateway.test"+tt.path, tt.body))
		})
	}
}

func TestUnsupportedURLs(t *testing.T) {
	require.Nil(t, parseResponseForURL("", `{"model":"gpt","usage":{}}`))
	kind, usage := ClassifyURL(nil)
	require.Nil(t, ParseResponse(kind, usage, nil))
	require.Nil(t, ParseResponse(unknownResponse, &providers.Usage{}, nil))
	for _, rawURL := range []string{
		"https://gateway.test/other", "ftp://gateway.test/v1/responses", "/v1/responses", "https:///v1/responses",
		"https://gateway.test/%zz/responses", "https://gateway.test/publishers/other/models/claude:rawPredict",
		"https://gateway.test/models/foo/bar:generateContent", "https://gateway.test/model/foo/bar/converse",
		"https://gateway.test/v1/responses/", "https://gateway.test/other?next=/v1/responses",
		"https://gateway.test/v1beta/interactions/123", "https://gateway.test/v1beta/interactions/123/cancel",
		"https://gateway.test/v1beta/interactions/", "https://gateway.test/models/foo:bar:generateContent",
		"https://gateway.test/model//invoke", "https://gateway.test/models/:generateContent",
	} {
		t.Run(rawURL, func(t *testing.T) {
			require.Nil(t, parseResponseForURL(rawURL, `{"model":"gpt","usage":{}}`))
		})
	}
}

func TestProviderOrigin(t *testing.T) {
	for rawURL, origin := range map[string]string{
		"HTTP://Example.test:80":    "http://example.test",
		"http://[::1]:8080":         "http://[::1]:8080",
		"https://Example.test:8443": "https://example.test:8443",
	} {
		t.Run(rawURL, func(t *testing.T) {
			call := parseResponseForURL(rawURL+"/v1/responses?key=secret#fragment", `{"model":"gpt","usage":{}}`)
			require.NotNil(t, call)
			require.Equal(t, origin, call.Provider)
		})
	}
}

func TestClassifyURLOwnsDerivedStrings(t *testing.T) {
	for _, tt := range []struct{ path, body string }{
		{"/model/claude/converse", `{"usage":{"inputTokens":1}}`},
		{"/model/claude/invoke", `{"usage":{"input_tokens":1}}`},
		{"/models/claude:generateContent", `{"usageMetadata":{"promptTokenCount":1}}`},
	} {
		t.Run(tt.path, func(t *testing.T) {
			buffer := []byte("https://gateway.test" + tt.path)
			borrowedURL := unsafe.String(unsafe.SliceData(buffer), len(buffer))
			u, err := url.Parse(borrowedURL)
			require.NoError(t, err)
			kind, usage := ClassifyURL(u)
			clear(buffer)
			call := ParseResponse(kind, usage, []byte(tt.body))
			require.NotNil(t, call)
			require.Equal(t, "claude", call.Model)
			require.Equal(t, "https://gateway.test", call.Provider)
		})
	}
}

func TestTokenCounts(t *testing.T) {
	for _, value := range []string{"-1", "1.5", "1e2", `"10"`, "true", "{}", "[]", "9223372036854775808", "18446744073709551615"} {
		t.Run(value, func(t *testing.T) {
			body := fmt.Sprintf(`{"model":"gpt","usage":{"input_tokens":%s,"output_tokens":5}}`, value)
			require.Nil(t, parseResponseForURL("https://gateway.test/v1/responses", body))
		})
	}
	for _, value := range []int64{1 << 53, math.MaxInt64} {
		body := fmt.Sprintf(`{"model":"gpt","usage":{"input_tokens":%d}}`, value)
		call := parseResponseForURL("https://gateway.test/v1/responses", body)
		require.NotNil(t, call)
		require.Equal(t, value, call.Input)
	}
	call := parseResponseForURL("https://gateway.test/v1/responses", `{"model":"gpt","usage":{"input_tokens":null,"output_tokens":5}}`)
	require.NotNil(t, call)
	require.Zero(t, call.Input)
	require.Equal(t, int64(5), call.Output)
}
