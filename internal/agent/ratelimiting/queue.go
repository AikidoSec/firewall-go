package ratelimiting

type queue struct {
	items []int
}

func (q *queue) Push(item int) {
	q.items = append(q.items, item)
}

func (q *queue) Pop() int {
	if len(q.items) == 0 {
		return -1
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item
}

func (q *queue) IsEmpty() bool {
	return q.Length() == 0
}

func (q *queue) IncrementLast() {
	if q.IsEmpty() {
		return
	}
	q.items[q.Length()-1] += 1
}

func (q *queue) Length() int {
	return len(q.items)
}
