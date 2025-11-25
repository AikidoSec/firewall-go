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

// Check checks if the request is part of an attack wave
// Returns true if an attack wave is detected and should be reported
func (d *Detector) Check(ctx *request.Context) bool {
	if ctx == nil || ctx.RemoteAddress == nil || *ctx.RemoteAddress == "" {
		return false
	}

	// @todo check if we've recently sent an event for this IP

	// @todo check if suspicious

	// @todo record suspicious requests

	// @todo count suspicious requests, if over threshold, then true

	return false
}
