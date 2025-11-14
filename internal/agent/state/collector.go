package state

import (
	"sync"
)

type Collector struct {
	mu        sync.Mutex
	hostnames map[string]map[uint32]uint64
}

func NewCollector() *Collector {
	return &Collector{
		hostnames: make(map[string]map[uint32]uint64),
	}
}
