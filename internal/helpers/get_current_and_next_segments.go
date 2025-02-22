package helpers

type Segment[T any] struct {
	CurrentSegment T
	NextSegment    T
}

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
