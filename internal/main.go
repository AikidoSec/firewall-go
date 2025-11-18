package internal

import (
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/zeninternals"
)

// Init initializes the firewall system by loading the zen-internals library
// and defining transit handlers. Returns an error if zen-internals fails to load.
func Init() error {
	err := zeninternals.Init()
	if err != nil {
		log.Error("failed to load zen internals", slog.Any("error", err))
		return err
	}

	return nil
}
