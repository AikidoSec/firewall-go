package stats

import "sync"

type aiProviderData struct {
	calls        int
	inputTokens  int
	outputTokens int
}

type AIStats struct {
	mu        sync.Mutex
	providers map[string]aiProviderData // key: "provider:model"
}

func newAIStats() *AIStats {
	return &AIStats{
		providers: make(map[string]aiProviderData),
	}
}

func (a *AIStats) OnAICall(data AICallData) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := data.Provider + ":" + data.Model
	entry := a.providers[key]
	entry.calls++
	entry.inputTokens += data.InputTokens
	entry.outputTokens += data.OutputTokens
	a.providers[key] = entry
}

func (a *AIStats) GetAndClear() []AIProviderStats {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.providers) == 0 {
		return nil
	}

	result := make([]AIProviderStats, 0, len(a.providers))
	for key, data := range a.providers {
		provider, model := splitProviderKey(key)
		result = append(result, AIProviderStats{
			Provider: provider,
			Model:    model,
			Calls:    data.calls,
			Tokens: AITokenStats{
				Input:  data.inputTokens,
				Output: data.outputTokens,
				Total:  data.inputTokens + data.outputTokens,
			},
		})
	}

	a.providers = make(map[string]aiProviderData)
	return result
}

func (a *AIStats) IsEmpty() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.providers) == 0
}

func splitProviderKey(key string) (string, string) {
	for i, c := range key {
		if c == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
