package main

import (
	"C"
	"github.com/AikidoSec/zen-internals-agent/zen_go_bindings"
)

//export AgentInit
func AgentInit(initJson string) (initOk bool) {
	return zen_go_bindings.AgentInit(initJson)
}

//export AgentUninit
func AgentUninit() {
	zen_go_bindings.AgentUninit()
}

func main() {}
