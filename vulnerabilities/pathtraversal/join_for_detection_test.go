package pathtraversal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinElementsForDetection(t *testing.T) {
	tests := []struct {
		name      string
		elems     []string
		separator string
		expected  string
	}{
		{
			name:      "inserts separator between plain elements",
			elems:     []string{"a", "b", "c"},
			separator: "/",
			expected:  "a/b/c",
		},
		{
			name:      "does not double a separator already at the end of an element",
			elems:     []string{"/tmp/", "../etc"},
			separator: "/",
			expected:  "/tmp/../etc",
		},
		{
			name:      "does not double a separator already at the start of an element",
			elems:     []string{"/tmp", "/../etc"},
			separator: "/",
			expected:  "/tmp/../etc",
		},
		{
			name:      "keeps a bare .. as its own delimited segment",
			elems:     []string{"/var/www/uploads", ".."},
			separator: "/",
			expected:  "/var/www/uploads/..",
		},
		{
			name:      "supports non-slash separators",
			elems:     []string{`C:\uploads`, ".."},
			separator: `\`,
			expected:  `C:\uploads\..`,
		},
		{
			name:      "single element is returned unchanged",
			elems:     []string{"solo"},
			separator: "/",
			expected:  "solo",
		},
		{
			name:      "no elements returns an empty string",
			elems:     []string{},
			separator: "/",
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, JoinElementsForDetection(tt.elems, tt.separator))
		})
	}
}
