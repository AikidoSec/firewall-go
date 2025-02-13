package helpers

// Segment represents a pair of current and next segments
type Segment[T any] struct {
	CurrentSegment T
	NextSegment    T
}

// GetCurrentAndNextSegments returns a slice of segments containing current and next items
func GetCurrentAndNextSegments[T any](array []T) []Segment[T] {
	var segments []Segment[T]
	for i := 0; i < len(array)-1; i++ {
		segments = append(segments, Segment[T]{
			CurrentSegment: array[i],
			NextSegment:    array[i+1],
		})
	}
	return segments
}
