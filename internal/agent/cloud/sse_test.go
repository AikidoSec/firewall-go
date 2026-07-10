package cloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func feedLines(p *sseParser, lines ...string) (sseEvent, bool) {
	var event sseEvent
	var ok bool
	for _, line := range lines {
		event, ok = p.feedLine(line)
	}
	return event, ok
}

func TestSSEParserFeedLine(t *testing.T) {
	t.Run("does not dispatch on non-blank lines", func(t *testing.T) {
		p := &sseParser{}

		_, ok := p.feedLine("event: config-updated")
		assert.False(t, ok)

		_, ok = p.feedLine(`data: {"configUpdatedAt":100}`)
		assert.False(t, ok)
	})

	t.Run("dispatches event with name and data on blank line", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			"event: config-updated",
			`data: {"configUpdatedAt":100}`,
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, `{"configUpdatedAt":100}`, event.data)
	})

	t.Run("multiple data lines are joined with newlines", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			"event: config-updated",
			"data: line one",
			"data: line two",
			"data: line three",
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, "line one\nline two\nline three", event.data)
	})

	t.Run("ignores comment lines", func(t *testing.T) {
		p := &sseParser{}
		event, ok := feedLines(p,
			": ping",
			"event: config-updated",
			`data: {"configUpdatedAt":100}`,
			"",
		)

		require.True(t, ok)
		assert.Equal(t, "config-updated", event.name)
		assert.Equal(t, `{"configUpdatedAt":100}`, event.data)
	})

	t.Run("resets state after dispatching", func(t *testing.T) {
		p := &sseParser{}
		feedLines(p, "event: config-updated", `data: {"configUpdatedAt":100}`, "")

		event, ok := feedLines(p, "")

		require.True(t, ok)
		assert.Equal(t, "", event.name)
		assert.Equal(t, "", event.data)
	})
}
