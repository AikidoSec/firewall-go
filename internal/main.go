package internal

import "github.com/AikidoSec/firewall-go/internal/vulnerabilities/zeninternals"

func Init() {
	zeninternals.Init()
	DefineTransits()
}
