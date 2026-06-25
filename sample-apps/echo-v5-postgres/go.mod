module echo-postgres

go 1.25.5

require (
	github.com/AikidoSec/firewall-go v1.2.5
	github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v5 v0.0.0-00010101000000-000000000000
	github.com/labstack/echo/v5 v5.0.3
	github.com/lib/pq v1.10.2
)

require (
	github.com/AikidoSec/firewall-go/cmd/zen-go v0.0.0-00010101000000-000000000000 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/bubbletea v1.1.0 // indirect
	github.com/charmbracelet/lipgloss v0.13.0 // indirect
	github.com/charmbracelet/x/ansi v0.2.3 // indirect
	github.com/charmbracelet/x/term v0.2.0 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.15.3-0.20240618155329-98d742f6907a // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/shirou/gopsutil/v4 v4.25.12 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/urfave/cli/v3 v3.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AikidoSec/firewall-go => ../../

replace github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v5 => ../../instrumentation/sources/labstack/echo.v5

replace github.com/AikidoSec/firewall-go/cmd/zen-go => ../../cmd/zen-go

tool github.com/AikidoSec/firewall-go/cmd/zen-go
