package internal

import "github.com/AikidoSec/firewall-go/internal/vulnerabilities/zen_internals"

func Init() {
	zen_internals.Init()
	DefineTransits()
}
