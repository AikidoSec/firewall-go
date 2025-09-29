package context

import "sync"

// Store is a global variable
var Store *ThreadLocal

// ThreadLocal is a simple implementation of thread-local storage.
type ThreadLocal struct {
	mu    sync.Mutex
	store map[int]Context
}

// Set sets a value for the current goroutine.
func Set(ctx Context) {
	if Store == nil {
		Store = newContextStore() // Create new global store if it doesn't exist.
	}
	Store.mu.Lock()
	defer Store.mu.Unlock()
	Store.store[getGoroutineID()] = ctx
}

// Get retrieves the value for the current goroutine.
func Get() *Context {
	if Store == nil {
		Store = newContextStore() // Create new global store if it doesn't exist.
	}
	Store.mu.Lock()
	defer Store.mu.Unlock()
	if ctx, exists := Store.store[getGoroutineID()]; exists {
		return &ctx
	}
	return nil
}

// NewContextStore creates a new ThreadLocal instance.
func newContextStore() *ThreadLocal {
	return &ThreadLocal{
		store: make(map[int]Context),
	}
}
