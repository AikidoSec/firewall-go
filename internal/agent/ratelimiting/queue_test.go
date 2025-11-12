package ratelimiting

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueue_Push(t *testing.T) {
	q := queue{}

	q.Push(1)
	assert.Equal(t, 1, q.Length())
	assert.False(t, q.IsEmpty())

	q.Push(2)
	assert.Equal(t, 2, q.Length())

	q.Push(3)
	assert.Equal(t, 3, q.Length())
}

func TestQueue_Pop(t *testing.T) {
	q := queue{}
	q.Push(1)
	q.Push(2)
	q.Push(3)

	item := q.Pop()
	assert.Equal(t, 1, item)
	assert.Equal(t, 2, q.Length())
	assert.False(t, q.IsEmpty())

	item = q.Pop()
	assert.Equal(t, 2, item)
	assert.Equal(t, 1, q.Length())

	item = q.Pop()
	assert.Equal(t, 3, item)
	assert.Equal(t, 0, q.Length())
	assert.True(t, q.IsEmpty())

	// Pop from empty queue
	item = q.Pop()
	assert.Equal(t, -1, item)
	assert.Equal(t, 0, q.Length())
	assert.True(t, q.IsEmpty())
}

func TestQueue_IsEmpty(t *testing.T) {
	q := queue{}
	assert.True(t, q.IsEmpty())

	q.Push(1)
	assert.False(t, q.IsEmpty())

	q.Pop()
	assert.True(t, q.IsEmpty())
}

func TestQueue_IncrementLast(t *testing.T) {
	q := queue{}

	// IncrementLast on empty queue should do nothing
	q.IncrementLast()
	assert.True(t, q.IsEmpty())

	q.Push(5)
	q.IncrementLast()
	// Verify by popping - should get 6
	item := q.Pop()
	assert.Equal(t, 6, item)

	q.Push(10)
	q.Push(20)
	q.IncrementLast()
	// Verify by popping - first should be 10, last should be 21
	assert.Equal(t, 10, q.Pop())
	assert.Equal(t, 21, q.Pop())
}

func TestQueue_Length(t *testing.T) {
	q := queue{}
	assert.Equal(t, 0, q.Length())

	q.Push(1)
	assert.Equal(t, 1, q.Length())

	q.Push(2)
	assert.Equal(t, 2, q.Length())

	q.Pop()
	assert.Equal(t, 1, q.Length())

	q.Pop()
	assert.Equal(t, 0, q.Length())
}
