package helpers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetCurrentAndNextSegments(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(GetCurrentAndNextSegments([]string{}), []Segment[string](nil))
	assert.Equal(GetCurrentAndNextSegments([]string{"a"}), []Segment[string](nil))
	assert.Equal(GetCurrentAndNextSegments([]string{"a", "b"}), []Segment[string]{
		{CurrentSegment: "a", NextSegment: "b"},
	})
	assert.Equal(GetCurrentAndNextSegments([]string{"a", "b", "c"}), []Segment[string]{
		{CurrentSegment: "a", NextSegment: "b"},
		{CurrentSegment: "b", NextSegment: "c"},
	})
	assert.Equal(GetCurrentAndNextSegments([]string{"a", "b", "c", "d"}), []Segment[string]{
		{CurrentSegment: "a", NextSegment: "b"},
		{CurrentSegment: "b", NextSegment: "c"},
		{CurrentSegment: "c", NextSegment: "d"},
	})
}
