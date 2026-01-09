package examine

import (
	"github.com/AikidoSec/firewall-go/instrumentation/transits"
)

func SetupTransits() {
	transits.SetTransits(
		examinePath,
		examineCommand,
	)
}
