package main

import (
	"github.com/wingaturumqi/mcp-audit/cmd"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	cmd.SetVersion(version, commit)
	cmd.Execute()
}
