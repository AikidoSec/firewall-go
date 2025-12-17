package attackwave

import (
	"container/list"
	"sync"
	"time"
)

type entry struct {
	key    string
	value  int
	expiry time.Time
}

type lruCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	list     *list.List // Front = most recent, Back = least recent
}

func newLRUCache(capacity int, ttl time.Duration) *lruCache {
	return &lruCache{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *lruCache) Get(key string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if !exists {
		return 0, false
	}

	ent := elem.Value.(*entry)

	// Check if expired
	if c.ttl > 0 && time.Now().After(ent.expiry) {
		c.removeElement(elem)
		return 0, false
	}

	// Move to front (most recently used)
	c.list.MoveToFront(elem)
	return ent.value, true
}

func (c *lruCache) Set(key string, value int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiry := time.Time{}
	if c.ttl > 0 {
		expiry = now.Add(c.ttl)
	}

	// Update existing entry
	if elem, exists := c.items[key]; exists {
		ent := elem.Value.(*entry)
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
	ent := &entry{
		key:    key,
		value:  value,
		expiry: expiry,
	}
	elem := c.list.PushFront(ent)
	c.items[key] = elem
}

func (c *lruCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.items[key]; exists {
		c.removeElement(elem)
	}
}

func (c *lruCache) evictOldest() {
	elem := c.list.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *lruCache) removeElement(elem *list.Element) {
	c.list.Remove(elem)
	ent := elem.Value.(*entry)
	delete(c.items, ent.key)
}

func (c *lruCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list.Len()
}

func (c *lruCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.list.Init()
}
