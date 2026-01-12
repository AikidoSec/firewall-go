package attackwave

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/request"
)

// Detector tracks suspicious requests per IP and reports attack waves
type Detector struct {
	// attackWaveThreshold is the number of suspicious requests needed within the time frame to trigger an alert
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
	options := &Options{}
	if opts != nil {
		options.AttackWaveThreshold = opts.AttackWaveThreshold
		options.AttackWaveTimeFrame = opts.AttackWaveTimeFrame
		options.MinTimeBetweenReports = opts.MinTimeBetweenReports
	}

	// Set defaults
	if options.AttackWaveThreshold == 0 {
		options.AttackWaveThreshold = 15
	}
	if options.AttackWaveTimeFrame == 0 {
		options.AttackWaveTimeFrame = 60 * time.Second
	}
	if options.MinTimeBetweenReports == 0 {
		options.MinTimeBetweenReports = 20 * time.Minute
	}

	return &Detector{
		attackWaveThreshold:   options.AttackWaveThreshold,
		attackWaveTimeFrame:   options.AttackWaveTimeFrame,
		minTimeBetweenReports: options.MinTimeBetweenReports,

		suspiciousRequests: newLRUCache(10_000, options.AttackWaveTimeFrame),
		recentReports:      newLRUCache(10_000, options.MinTimeBetweenReports),
	}
}

// CheckRequest checks if the request is part of an attack wave
// Returns true if an attack wave is detected and should be reported
func (d *Detector) CheckRequest(ctx *request.Context) bool {
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

	overLimit := d.addSuspiciousRequest(ip)
	if !overLimit {
		return false
	}

	d.recentReports.Set(ip, 1)

	return true
}

// addSuspiciousRequest adds a new request timestamp to the sliding window for that IP
// Returns true if request should be reported
func (d *Detector) addSuspiciousRequest(ip string) bool {
	timestamps, _ := d.suspiciousRequests.Get(ip)
	d.suspiciousRequests.Set(ip, timestamps+1)

	return timestamps+1 >= d.attackWaveThreshold
}
