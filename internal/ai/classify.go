package ai

import (
	"net/url"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/ai/providers"
)

type ResponseKind uint8

const (
	unknownResponse ResponseKind = iota
	openAIChat
	openAIResponses
	anthropic
	gemini
	bedrockConverse
	bedrockInvoke
	geminiInteraction
)

func ClassifyURL(u *url.URL) (ResponseKind, *providers.Usage) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return unknownResponse, nil
	}
	kind, model := classifyPath(u.EscapedPath())
	if kind == unknownResponse {
		return kind, nil
	}
	host := strings.ToLower(u.Host)
	if u.Scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	} else {
		host = strings.TrimSuffix(host, ":443")
	}
	origin := url.URL{Scheme: u.Scheme, Host: host}
	return kind, &providers.Usage{Provider: origin.String(), Model: model}
}

func IsRequestPath(path string) bool {
	kind, _ := classifyPath(path)
	return kind != unknownResponse
}

func classifyPath(path string) (ResponseKind, string) {
	if strings.HasSuffix(path, "/chat/completions") {
		return openAIChat, ""
	} else if strings.HasSuffix(path, "/responses") {
		return openAIResponses, ""
	} else if strings.HasSuffix(path, "/v1/messages") || modelInPath(path, "/publishers/anthropic/models/", ":rawPredict") != "" {
		return anthropic, ""
	} else if strings.HasSuffix(path, "/interactions") {
		return geminiInteraction, ""
	} else if model := modelInPath(path, "/models/", ":generateContent"); model != "" && !strings.Contains(model, ":") {
		return gemini, model
	} else if model := modelInPath(path, "/model/", "/converse"); model != "" {
		return bedrockConverse, model
	} else if model := modelInPath(path, "/model/", "/invoke"); model != "" {
		return bedrockInvoke, model
	}
	return unknownResponse, ""
}

func modelInPath(path, prefix, suffix string) string {
	path, ok := strings.CutSuffix(path, suffix)
	if !ok {
		return ""
	}
	start := strings.LastIndex(path, prefix)
	if start == -1 {
		return ""
	}
	model := path[start+len(prefix):]
	if strings.Contains(model, "/") {
		return ""
	}
	return strings.Clone(model)
}
