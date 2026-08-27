package stats

import "sync"

type providerModelKey struct {
	provider string
	model    string
}

type aiProviderData struct {
	calls        int
	inputTokens  int
	outputTokens int
}

type AIStats struct {
	mu        sync.Mutex
	providers map[providerModelKey]aiProviderData
}

func newAIStats() *AIStats {
	return &AIStats{
		providers: make(map[providerModelKey]aiProviderData),
	}
}

func (a *AIStats) OnAICall(data AICallData) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := providerModelKey{provider: data.Provider, model: data.Model}
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
		result = append(result, AIProviderStats{
			Provider: key.provider,
			Model:    key.model,
			Calls:    data.calls,
			Tokens: AITokenStats{
				Input:  data.inputTokens,
				Output: data.outputTokens,
				Total:  data.inputTokens + data.outputTokens,
			},
		})
	}

	a.providers = make(map[providerModelKey]aiProviderData)
	return result
}

func (a *AIStats) IsEmpty() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.providers) == 0
}
