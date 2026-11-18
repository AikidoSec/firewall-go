package http

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
)

var (
	geminiPath          = regexp.MustCompile(`/models/([^/:]+):generateContent$`)
	bedrockPath         = regexp.MustCompile(`/model/([^/]+)/(converse|invoke)$`)
	anthropicVertexPath = regexp.MustCompile(`/publishers/anthropic/models/[^/]+:rawPredict$`)
)

func isAIRequestPath(path string) bool {
	return strings.HasSuffix(path, "/chat/completions") || strings.HasSuffix(path, "/responses") ||
		strings.HasSuffix(path, "/v1/messages") || geminiPath.MatchString(path) ||
		bedrockPath.MatchString(path) || anthropicVertexPath.MatchString(path)
}

// Decode only metadata; prompt and response content are not retained in the result.
func parseAIResponse(u *url.URL, data []byte) (call aiCall, ok bool) {
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil || body == nil {
		return call, false
	}

	call.provider = (&url.URL{Scheme: strings.ToLower(u.Scheme), Host: strings.ToLower(u.Host)}).String()
	call.model = jsonString(body["model"])

	usage := jsonObject(body["usage"])
	input, output := "input_tokens", "output_tokens"

	switch path := u.EscapedPath(); {
	case strings.HasSuffix(path, "/chat/completions"):
		input, output = "prompt_tokens", "completion_tokens"

	case strings.HasSuffix(path, "/responses"):

	case strings.HasSuffix(path, "/v1/messages") || anthropicVertexPath.MatchString(path):

	case geminiPath.MatchString(path):
		match := geminiPath.FindStringSubmatch(path)
		call.model, _ = url.PathUnescape(match[1])
		if model := jsonString(body["modelVersion"]); model != "" {
			call.model = model
		}

		usage = jsonObject(body["usageMetadata"])
		call.input = tokenCount(usage["promptTokenCount"]) + tokenCount(usage["toolUsePromptTokenCount"])
		call.output = tokenCount(usage["candidatesTokenCount"]) + tokenCount(usage["thoughtsTokenCount"])

		return call, call.model != ""

	case bedrockPath.MatchString(path):
		match := bedrockPath.FindStringSubmatch(path)
		model, err := url.PathUnescape(match[1])
		if err != nil {
			return call, false
		}

		if !strings.HasPrefix(model, "arn:") {
			call.model = model
		}

		if match[2] == "converse" {
			input, output = "inputTokens", "outputTokens"
		}

	default:
		return call, false
	}

	call.input = tokenCount(usage[input])
	call.output = tokenCount(usage[output])

	return call, call.model != ""
}

type aiCall struct {
	provider, model string
	input, output   int
}

func (c aiCall) record() {
	hooks.OnAICall(c.provider, c.model, c.input, c.output)
}

func jsonObject(raw json.RawMessage) map[string]json.RawMessage {
	var result map[string]json.RawMessage
	_ = json.Unmarshal(raw, &result)
	return result
}

func jsonString(raw json.RawMessage) string {
	var result string
	_ = json.Unmarshal(raw, &result)
	return result
}

func tokenCount(raw json.RawMessage) int {
	var n int
	if json.Unmarshal(raw, &n) != nil || n < 0 {
		return 0
	}
	return n
}
