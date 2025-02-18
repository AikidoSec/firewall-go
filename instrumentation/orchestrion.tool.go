package main

import (
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/database_sql"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic"
)
