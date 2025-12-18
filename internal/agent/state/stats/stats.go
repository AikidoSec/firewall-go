package stats

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

const (
	minStatsCollectedForRelevantMetrics = 10000
)

type Stats struct {
	startedAt            int64
	requests             int
	requestsAborted      int
	requestsRateLimited  int
	attacks              int
	attacksBlocked       int
	monitoredSinkTimings map[string]aikido_types.MonitoredSinkTimings

	mu sync.Mutex
}

func New() *Stats {
	return &Stats{
		monitoredSinkTimings: make(map[string]aikido_types.MonitoredSinkTimings),
	}
}

func (s *Stats) GetAndClear() aikido_types.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := aikido_types.Stats{
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
		Sinks: s.getAndClearSinks(),
	}

	s.startedAt = utils.GetTime()
	s.requests = 0
	s.requestsAborted = 0
	s.requestsRateLimited = 0
	s.attacks = 0
	s.attacksBlocked = 0

	return result
}

func (s *Stats) getAndClearSinks() map[string]aikido_types.MonitoredSinkStats {
	monitoredSinkStats := make(map[string]aikido_types.MonitoredSinkStats)
	for sink, stats := range s.monitoredSinkTimings {
		if stats.Total <= minStatsCollectedForRelevantMetrics {
			continue
		}

		monitoredSinkStats[sink] = aikido_types.MonitoredSinkStats{
			AttacksDetected:       stats.AttacksDetected,
			InterceptorThrewError: stats.InterceptorThrewError,
			WithoutContext:        stats.WithoutContext,
			Total:                 stats.Total,
			CompressedTimings: []aikido_types.CompressedTiming{
				{
					AverageInMS:  computeAverage(stats.Timings),
					Percentiles:  computePercentiles(stats.Timings),
					CompressedAt: utils.GetTime(),
				},
			},
		}

		delete(s.monitoredSinkTimings, sink)
	}
	return monitoredSinkStats
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

func (s *Stats) OnSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	s.mu.Lock()
	defer s.mu.Unlock()

	monitoredSinkTimings, found := s.monitoredSinkTimings[sink]
	if !found {
		monitoredSinkTimings = aikido_types.MonitoredSinkTimings{}
	}

	monitoredSinkTimings.AttacksDetected.Total += int(stats.AttacksDetected.Total)
	monitoredSinkTimings.AttacksDetected.Blocked += int(stats.AttacksDetected.Blocked)
	monitoredSinkTimings.InterceptorThrewError += int(stats.InterceptorThrewError)
	monitoredSinkTimings.WithoutContext += int(stats.WithoutContext)
	monitoredSinkTimings.Total += int(stats.Total)
	monitoredSinkTimings.Timings = append(monitoredSinkTimings.Timings, stats.Timings...)

	s.monitoredSinkTimings[sink] = monitoredSinkTimings
}

func (s *Stats) OnRateLimit() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requestsRateLimited++
}
