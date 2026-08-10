package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
)

// Shutdown reports any data Zen has collected but not yet sent, then stops
// Zen's background processes. Call this before your application exits so
// recent data is not lost.
func Shutdown(ctx context.Context) error {
	return agent.AgentUninit(ctx)
}
