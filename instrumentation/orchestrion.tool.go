package main

import (
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/path/filepath"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo"
)
