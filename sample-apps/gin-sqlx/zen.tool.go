// This file was created by 'zen-go init', and is used to ensure the
// go.mod file contains the necessary entries for repeatable builds.

package main

import (
	// Ensures Aikido Zen instrumentation is present in go.mod
	// Do not remove this unless you want to stop using Aikido.
	_ "github.com/AikidoSec/firewall-go/instrumentation"

	// Aikido Zen: Sources
	_ "github.com/AikidoSec/firewall-go/instrumentation/sources/gin-gonic/gin"
)
