package attackwave

import (
	"container/list"
	"sync"
	"time"
)

type entry[T any] struct {
	key    string
	value  T
	expiry time.Time
}

type lruCache[T any] struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	list     *list.List // Front = most recent, Back = least recent
}

func newLRUCache[T any](capacity int, ttl time.Duration) *lruCache[T] {
	return &lruCache[T]{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *lruCache[T]) Get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero T
	elem, exists := c.items[key]
	if !exists {
		return zero, false
	}

	ent := elem.Value.(*entry[T])

	// Check if expired
	if time.Now().After(ent.expiry) {
		c.removeElement(elem)
		return zero, false
	}

	// Move to front (most recently used)
	c.list.MoveToFront(elem)
	return ent.value, true
}

func (c *lruCache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiry := now.Add(c.ttl)

	// Update existing entry
	if elem, exists := c.items[key]; exists {
		ent := elem.Value.(*entry[T])
		ent.value = value
		ent.expiry = expiry
		c.list.MoveToFront(elem)
		return
	}

	// Evict if at capacity
	if c.list.Len() >= c.capacity {
		c.evictOldest()
	}

	// Add new entry
	ent := &entry[T]{
		key:    key,
		value:  value,
		expiry: expiry,
	}
	elem := c.list.PushFront(ent)
	c.items[key] = elem
}

func (c *lruCache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[key]; exists {
		c.removeElement(elem)
	}
}

func (c *lruCache[T]) evictOldest() {
	elem := c.list.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *lruCache[T]) removeElement(elem *list.Element) {
	c.list.Remove(elem)
	ent := elem.Value.(*entry[T])
	delete(c.items, ent.key)
}

func (c *lruCache[T]) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list.Len()
}

func (c *lruCache[T]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.list.Init()
}
