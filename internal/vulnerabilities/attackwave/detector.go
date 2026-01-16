package attackwave

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/request"
)

// Sample represents a suspicious request sample with method and URL
type Sample struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

// suspiciousRequestData holds the count and samples for an IP
type suspiciousRequestData struct {
	count   int
	samples []Sample
}

// Detector tracks suspicious requests per IP and reports attack waves
type Detector struct {
	// attackWaveThreshold is the number of suspicious requests needed within the time frame to trigger an alert
	attackWaveThreshold int
	// attackWaveTimeFrame is the time window for counting suspicious requests
	attackWaveTimeFrame time.Duration
	// minTimeBetweenReports gives a minimum time period between reporting a new attack wave for an IP
	minTimeBetweenReports time.Duration
	// maxSamplesPerIP is the maximum number of samples to keep per IP
	maxSamplesPerIP int

	suspiciousRequests *lruCache[*suspiciousRequestData]

	// recentReports tracks IPs we've recently reported (value is unused, only presence matters)
	recentReports *lruCache[struct{}]
}

type Options struct {
	AttackWaveThreshold   int
	AttackWaveTimeFrame   time.Duration
	MinTimeBetweenReports time.Duration
	MaxSamplesPerIP       int
}

func NewDetector(opts *Options) *Detector {
	options := &Options{}
	if opts != nil {
		options.AttackWaveThreshold = opts.AttackWaveThreshold
		options.AttackWaveTimeFrame = opts.AttackWaveTimeFrame
		options.MinTimeBetweenReports = opts.MinTimeBetweenReports
		options.MaxSamplesPerIP = opts.MaxSamplesPerIP
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
	if options.MaxSamplesPerIP == 0 {
		options.MaxSamplesPerIP = 15
	}

	return &Detector{
		attackWaveThreshold:   options.AttackWaveThreshold,
		attackWaveTimeFrame:   options.AttackWaveTimeFrame,
		minTimeBetweenReports: options.MinTimeBetweenReports,
		maxSamplesPerIP:       options.MaxSamplesPerIP,

		suspiciousRequests: newLRUCache[*suspiciousRequestData](10_000, options.AttackWaveTimeFrame),
		recentReports:      newLRUCache[struct{}](10_000, options.MinTimeBetweenReports),
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

	sample := Sample{
		Method: ctx.Method,
		URL:    ctx.URL,
	}

	overLimit := d.addSuspiciousRequest(ip, sample)
	if !overLimit {
		return false
	}

	d.recentReports.Set(ip, struct{}{})

	return true
}

// addSuspiciousRequest increments the count and tracks sample for the given IP
// Returns true if the threshold has been reached and should be reported
func (d *Detector) addSuspiciousRequest(ip string, sample Sample) bool {
	data, exists := d.suspiciousRequests.Get(ip)
	if !exists || data == nil {
		data = &suspiciousRequestData{
			count:   0,
			samples: []Sample{},
		}
	}

	data.count++
	data.samples = d.trackSample(sample, data.samples)

	d.suspiciousRequests.Set(ip, data)

	return data.count >= d.attackWaveThreshold
}

// trackSample adds a sample if it's unique and we haven't reached the max
func (d *Detector) trackSample(sample Sample, samples []Sample) []Sample {
	if len(samples) >= d.maxSamplesPerIP {
		return samples
	}

	// Only store unique samples
	for _, s := range samples {
		if s.Method == sample.Method && s.URL == sample.URL {
			return samples
		}
	}

	return append(samples, sample)
}

// GetSamplesForIP returns the samples collected for the given IP
func (d *Detector) GetSamplesForIP(ip string) []Sample {
	data, exists := d.suspiciousRequests.Get(ip)
	if !exists || data == nil {
		return []Sample{}
	}
	return data.samples
}
