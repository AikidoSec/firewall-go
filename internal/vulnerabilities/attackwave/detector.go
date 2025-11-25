package attackwave

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/request"
)

// Detector tracks suspicious requests per IP and reports attack waves
type Detector struct {
	// attackWaveThreshold is the number of suspicious requests needed to trigger an alert
	attackWaveThreshold int
	// attackWaveTimeFrame is the time window for counting suspicious requests
	attackWaveTimeFrame time.Duration
	// minTimeBetweenReports gives a minimum time period between reporting a new attack wave for an IP
	minTimeBetweenReports time.Duration

	suspiciousRequests *lruCache

	// recentReports tracks IPs we've recently reported (value is unused, only presence matters)
	recentReports *lruCache
}

type Options struct {
	AttackWaveThreshold   int
	AttackWaveTimeFrame   time.Duration
	MinTimeBetweenReports time.Duration
}

func NewDetector(opts *Options) *Detector {
	if opts == nil {
		opts = &Options{}
	}

	// Set defaults
	if opts.AttackWaveThreshold == 0 {
		opts.AttackWaveThreshold = 15
	}
	if opts.AttackWaveTimeFrame == 0 {
		opts.AttackWaveTimeFrame = 60 * time.Second
	}
	if opts.MinTimeBetweenReports == 0 {
		opts.MinTimeBetweenReports = 20 * time.Minute
	}

	return &Detector{
		attackWaveThreshold:   opts.AttackWaveThreshold,
		attackWaveTimeFrame:   opts.AttackWaveTimeFrame,
		minTimeBetweenReports: opts.MinTimeBetweenReports,

		suspiciousRequests: newLRUCache(10_000, opts.AttackWaveTimeFrame),
		recentReports:      newLRUCache(10_000, opts.MinTimeBetweenReports),
	}
}

// Check checks if the request is part of an attack wave
// Returns true if an attack wave is detected and should be reported
func (d *Detector) Check(ctx *request.Context) bool {
	if ctx == nil || ctx.RemoteAddress == nil || *ctx.RemoteAddress == "" {
		return false
	}

	ip := *ctx.RemoteAddress

	// If we've reported an attack wave from this IP recently, just return false
	if _, exists := d.recentReports.Get(ip); exists {
		return false
	}

	if !isWebScanner(ctx) {
		return false
	}

	requestCount := d.addSuspiciousRequest(ip, time.Now())

	if requestCount < d.attackWaveThreshold {
		return false
	}

	d.recentReports.Set(ip, nil)

	return true
}

func (d *Detector) addSuspiciousRequest(ip string, timestamp time.Time) int {
	timestamps, _ := d.suspiciousRequests.Get(ip)

	// Filter out old timestamps outside the time window
	cutoff := timestamp.Add(-d.attackWaveTimeFrame)
	validTimestamps := make([]time.Time, 0, len(timestamps)+1)
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	validTimestamps = append(validTimestamps, timestamp)
	d.suspiciousRequests.Set(ip, validTimestamps)

	return len(validTimestamps)
}
