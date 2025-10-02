package main

import (
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/databasesql"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/gingonic"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/labstackecho"
)
