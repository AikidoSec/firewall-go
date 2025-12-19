package zeninternals

import (
	"errors"
	"sync"
	"time"
)

const (
	instanceMaxAge   = 5 * time.Minute
	maxIdleInstances = 10
)

type Pool struct {
	newInstance   func() *wasmInstance
	idleInstances []*wasmInstance

	mu sync.Mutex
}

func NewPool(newInstance func() *wasmInstance) *Pool {
	return &Pool{
		newInstance:   newInstance,
		idleInstances: make([]*wasmInstance, 0),
	}
}

func (p *Pool) Get() (*wasmInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Loop through max idle + 1 to ensure run through all available instances
	for range maxIdleInstances + 1 {
		instance := p.tryGetInstance()
		if instance != nil {
			return instance, nil
		}
	}

	return nil, errors.New("could not acquire instance")
}

func (p *Pool) tryGetInstance() *wasmInstance {
	if len(p.idleInstances) > 0 {
		instance := p.idleInstances[len(p.idleInstances)-1]
		p.idleInstances = p.idleInstances[:len(p.idleInstances)-1]

		// Check health of instance
		if instance.createdAt.Before(time.Now().Add(-instanceMaxAge)) {
			return nil
		}

		return instance
	}

	instance := p.newInstance()
	return instance
}

func (p *Pool) Put(instance *wasmInstance) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idleInstances) < maxIdleInstances {
		p.idleInstances = append(p.idleInstances, instance)
	}
}
