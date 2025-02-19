module github.com/AikidoSec/firewall-go

go 1.22.7

toolchain go1.23.6

require (
	github.com/AikidoSec/zen-internals-agent v0.0.0-00010101000000-000000000000
	github.com/seancfoley/ipaddress-go v1.7.0
	github.com/stretchr/testify v1.10.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.5
)

replace github.com/AikidoSec/zen-internals-agent => ./agent

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/seancfoley/bintree v1.3.1 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250212204824-5a70512c5d8b // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
