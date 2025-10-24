package internal

import (
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/zeninternals"
)

func Init() error {
	err := zeninternals.Init()
	if err != nil {
		log.Error("failed to load zen internals", slog.Any("error", err))
		return err
	}

	DefineTransits()

	return nil
}
