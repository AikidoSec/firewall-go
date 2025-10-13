package ratelimiting

type Queue struct {
	items []int
}

func (q *Queue) Push(item int) {
	q.items = append(q.items, item)
}

func (q *Queue) Pop() int {
	if len(q.items) == 0 {
		return -1
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item
}

func (q *Queue) IsEmpty() bool {
	return q.Length() == 0
}

func (q *Queue) IncrementLast() {
	if q.IsEmpty() {
		return
	}
	q.items[q.Length()-1] += 1
}

func (q *Queue) Length() int {
	return len(q.items)
}
