package main

import (
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/database/sql"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/jackc/pgx"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/os"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/os/exec"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/path"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sinks/path/filepath"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/labstack/echo"
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/net/http"
)
