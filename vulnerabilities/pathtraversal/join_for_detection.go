package pathtraversal

import "strings"

// JoinElementsForDetection rebuilds the path filepath.Join/path.Join would produce, minus
// the Clean() call that strips the ".." segments detection needs to see.
func JoinElementsForDetection(elems []string, separator string) string {
	var b strings.Builder
	for i, e := range elems {
		if i > 0 {
			prev := elems[i-1]
			if !strings.HasSuffix(prev, separator) && !strings.HasPrefix(e, separator) {
				b.WriteString(separator)
			}
		}
		b.WriteString(e)
	}
	return b.String()
}
