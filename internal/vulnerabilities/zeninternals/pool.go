package zeninternals

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/log"
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

	// Loop through max idle + 1 to ensure we can loop through all potentially expired instances,
	// and still get a new instance.
	for range maxIdleInstances + 1 {
		instance := p.tryGetInstance()
		if instance != nil {
			return instance, nil
		}
	}

	return nil, errors.New("could not acquire instance")
}

// tryGetInstance checks if there's an available idle instance. If there is,
// it will remove it from the idle list and return it. If not, it will create a new instance.
//
// This is an internal method and should not be used by consumers of the pool, use [Pool.Get].
//
// WARNING: caller must hold the pool mutex.
func (p *Pool) tryGetInstance() *wasmInstance {
	if len(p.idleInstances) == 0 {
		return p.newInstance()
	}

	instance := p.idleInstances[len(p.idleInstances)-1]
	p.idleInstances = p.idleInstances[:len(p.idleInstances)-1]

	// Discard if too old
	if time.Since(instance.createdAt) > instanceMaxAge {
		if instance.mod != nil {
			err := instance.mod.Close(context.Background())
			if err != nil {
				log.Debug("instance could not be closed", slog.Any("error", err))
			}
		}
		return nil
	}

	return instance
}

func (p *Pool) Put(instance *wasmInstance) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.idleInstances) < maxIdleInstances {
		p.idleInstances = append(p.idleInstances, instance)
	}
}
