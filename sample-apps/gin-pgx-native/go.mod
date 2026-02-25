module gin-pgx-native

go 1.24.2

require (
	github.com/AikidoSec/firewall-go v0.3.0
	github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5 v0.0.0-00010101000000-000000000000
	github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin v0.0.0-00010101000000-000000000000
	github.com/gin-gonic/gin v1.11.0
	github.com/jackc/pgx/v5 v5.8.0
)

require (
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.14.2 // indirect
	github.com/bytedance/sonic/loader v0.4.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.28.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.18.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.57.1 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace github.com/AikidoSec/firewall-go => ../../

replace github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin => ../../instrumentation/sources/gin-gonic/gin

replace github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx.v5 => ../../instrumentation/sinks/jackc/pgx.v5
