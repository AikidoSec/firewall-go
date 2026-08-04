package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIStats_OnAICall(t *testing.T) {
	t.Run("tracks single call", func(t *testing.T) {
		ai := newAIStats()

		ai.OnAICall(AICallData{
			Provider:     "openai",
			Model:        "gpt-4",
			InputTokens:  100,
			OutputTokens: 50,
		})

		result := ai.GetAndClear()
		require.Len(t, result, 1)
		assert.Equal(t, "openai", result[0].Provider)
		assert.Equal(t, "gpt-4", result[0].Model)
		assert.Equal(t, 1, result[0].Calls)
		assert.Equal(t, 100, result[0].Tokens.Input)
		assert.Equal(t, 50, result[0].Tokens.Output)
		assert.Equal(t, 150, result[0].Tokens.Total)
	})

	t.Run("aggregates multiple calls same provider/model", func(t *testing.T) {
		ai := newAIStats()

		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})
		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 200, OutputTokens: 100})

		result := ai.GetAndClear()
		require.Len(t, result, 1)
		assert.Equal(t, 2, result[0].Calls)
		assert.Equal(t, 300, result[0].Tokens.Input)
		assert.Equal(t, 150, result[0].Tokens.Output)
		assert.Equal(t, 450, result[0].Tokens.Total)
	})

	t.Run("tracks different providers separately", func(t *testing.T) {
		ai := newAIStats()

		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})
		ai.OnAICall(AICallData{Provider: "anthropic", Model: "claude-3", InputTokens: 200, OutputTokens: 100})

		result := ai.GetAndClear()
		assert.Len(t, result, 2)
	})

	t.Run("tracks different models separately", func(t *testing.T) {
		ai := newAIStats()

		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})
		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-3.5", InputTokens: 50, OutputTokens: 25})

		result := ai.GetAndClear()
		assert.Len(t, result, 2)
	})
}

func TestAIStats_GetAndClear(t *testing.T) {
	t.Run("returns nil when empty", func(t *testing.T) {
		ai := newAIStats()
		result := ai.GetAndClear()
		assert.Nil(t, result)
	})

	t.Run("clears after retrieval", func(t *testing.T) {
		ai := newAIStats()

		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})

		result1 := ai.GetAndClear()
		require.Len(t, result1, 1)

		result2 := ai.GetAndClear()
		assert.Nil(t, result2)
	})
}

func TestAIStats_IsEmpty(t *testing.T) {
	t.Run("empty when no calls", func(t *testing.T) {
		ai := newAIStats()
		assert.True(t, ai.IsEmpty())
	})

	t.Run("not empty after call", func(t *testing.T) {
		ai := newAIStats()
		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})
		assert.False(t, ai.IsEmpty())
	})

	t.Run("empty after clear", func(t *testing.T) {
		ai := newAIStats()
		ai.OnAICall(AICallData{Provider: "openai", Model: "gpt-4", InputTokens: 100, OutputTokens: 50})
		ai.GetAndClear()
		assert.True(t, ai.IsEmpty())
	})
}
