package main

import (
	_ "github.com/AikidoSec/firewall-go/internal/sinks/database_sql"
	_ "github.com/AikidoSec/firewall-go/internal/sinks/os"
	_ "github.com/AikidoSec/firewall-go/internal/sources/gin-gonic"
	_ "github.com/AikidoSec/firewall-go/internal/sources/labstack-echo"
)
