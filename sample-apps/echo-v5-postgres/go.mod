module echo-postgres

go 1.25.5

require (
	github.com/AikidoSec/firewall-go v1.0.0
	github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v5 v0.0.0-00010101000000-000000000000
	github.com/labstack/echo/v5 v5.0.3
	github.com/lib/pq v1.10.2
)

require (
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

replace github.com/AikidoSec/firewall-go => ../../

replace github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo.v5 => ../../instrumentation/sources/labstack/echo.v5
