package ai

import "github.com/AikidoSec/firewall-go/internal/ai/providers"

const maxBodyBytes = 2 * 1024 * 1024

func ParseResponse(kind ResponseKind, usage *providers.Usage, body []byte) *providers.Usage {
	if usage == nil || len(body) > maxBodyBytes {
		return nil
	}
	var parsed bool
	switch kind {
	case openAIChat:
		parsed = providers.ParseOpenAIChat(body, usage)
	case openAIResponses:
		parsed = providers.ParseOpenAIResponses(body, usage)
	case anthropic:
		parsed = providers.ParseAnthropic(body, usage)
	case gemini:
		parsed = providers.ParseGemini(body, usage)
	case geminiInteraction:
		parsed = providers.ParseGeminiInteraction(body, usage)
	case bedrockConverse:
		parsed = providers.ParseBedrockConverse(body, usage)
	case bedrockInvoke:
		parsed = providers.ParseBedrockInvoke(body, usage)
	}
	if !parsed || usage.Model == "" || len(usage.Model) > 256 {
		return nil
	}
	if usage.Input < 0 || usage.Output < 0 || usage.CacheRead < 0 || usage.CacheWrite < 0 {
		return nil
	}
	return usage
}
