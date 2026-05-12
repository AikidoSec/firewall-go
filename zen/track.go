package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func Track(ctx context.Context, eventName string, metadata any) {
	if config.IsZenDisabled() {
		return
	}

	if eventName == "" {
		log.Info("zen.Track(...) expects a non-empty string as event name.")
		return
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return
	}

	agent.OnTrackEvent(eventName, reqCtx.GetUserID(), reqCtx.GetIP(), metadata)
}
