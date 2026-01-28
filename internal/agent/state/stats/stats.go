package stats

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type operationData struct {
	kind            OperationKind
	total           int
	attacksDetected int
	attacksBlocked  int
}

type Stats struct {
	startedAt           int64
	requests            int
	requestsAborted     int
	requestsRateLimited int
	attacks             int
	attacksBlocked      int
	operations          map[string]operationData

	mu sync.Mutex
}

func New() *Stats {
	return &Stats{
		operations: make(map[string]operationData),
	}
}

func (s *Stats) GetAndClear() Data {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := Data{
		StartedAt: s.startedAt,
		EndedAt:   utils.GetTime(),
		Requests: aikido_types.Requests{
			Total:   s.requests,
			Aborted: s.requestsAborted,
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   s.attacks,
				Blocked: s.attacksBlocked,
			},
			RateLimited: s.requestsRateLimited,
		},
		Operations: s.getAndClearOperations(),
	}

	s.startedAt = utils.GetTime()
	s.requests = 0
	s.requestsAborted = 0
	s.requestsRateLimited = 0
	s.attacks = 0
	s.attacksBlocked = 0

	return result
}

func (s *Stats) SetStartedAt(startedAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.startedAt = startedAt
}

func (s *Stats) OnRequest() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests++
}

func (s *Stats) OnAttackDetected(blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attacks++
	if blocked {
		s.attacksBlocked++
	}
}

func (s *Stats) OnRateLimit() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requestsRateLimited++
}

func (s *Stats) OnOperationCall(operation string, kind OperationKind) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.operations == nil {
		s.operations = make(map[string]operationData)
	}

	data, found := s.operations[operation]
	if !found {
		data = operationData{
			kind: kind,
		}
	}
	data.total++
	s.operations[operation] = data
}

func (s *Stats) OnOperationAttack(operation string, blocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.operations == nil {
		return
	}

	data, found := s.operations[operation]
	if !found {
		// If operation wasn't registered, we can't track the attack
		return
	}
	data.attacksDetected++
	if blocked {
		data.attacksBlocked++
	}
	s.operations[operation] = data
}

func (s *Stats) getAndClearOperations() map[string]OperationStats {
	operations := make(map[string]OperationStats)

	if s.operations == nil {
		return operations
	}

	for operation, data := range s.operations {
		operations[operation] = OperationStats{
			Kind:  data.kind,
			Total: data.total,
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   data.attacksDetected,
				Blocked: data.attacksBlocked,
			},
		}
		delete(s.operations, operation)
	}
	return operations
}
