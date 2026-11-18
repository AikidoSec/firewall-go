package http

import (
	"net/url"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/internal/ai"
)

func isAIRequestPath(path string) bool {
	return ai.IsRequestPath(path)
}

// Decode only metadata; prompt and response content are not retained in the result.
func parseAIResponse(u *url.URL, data []byte) (call aiCall, ok bool) {
	kind, usage := ai.ClassifyURL(u)
	usage = ai.ParseResponse(kind, usage, data)
	if usage == nil {
		return call, false
	}
	// The stats API uses int, so reject counts that cannot be represented on this platform.
	input, output := int(usage.Input), int(usage.Output)
	if int64(input) != usage.Input || int64(output) != usage.Output {
		return call, false
	}
	return aiCall{usage.Provider, usage.Model, input, output}, true
}

type aiCall struct {
	provider, model string
	input, output   int
}

func (c aiCall) record() {
	hooks.OnAICall(c.provider, c.model, c.input, c.output)
}
