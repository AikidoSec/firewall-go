module github.com/AikidoSec/firewall-go

go 1.24

require (
	github.com/AikidoSec/zen-internals-agent v0.0.0-00010101000000-000000000000
	github.com/seancfoley/ipaddress-go v1.7.0
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.6
)

replace github.com/AikidoSec/zen-internals-agent => ./agent

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/seancfoley/bintree v1.3.1 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
