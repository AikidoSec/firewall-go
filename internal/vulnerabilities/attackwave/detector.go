package attackwave

import "time"

// Detector tracks suspicious requests per IP and reports attack waves
type Detector struct {
	// attackWaveThreshold is the number of suspicious requests needed to trigger an alert
	attackWaveThreshold int
	// attackWaveTimeFrame is the time window for counting suspicious requests
	attackWaveTimeFrame time.Duration
}

type Options struct {
	AttackWaveThreshold int
	AttackWaveTimeFrame time.Duration
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

	return &Detector{
		attackWaveThreshold: opts.AttackWaveThreshold,
		attackWaveTimeFrame: opts.AttackWaveTimeFrame,
	}
}
