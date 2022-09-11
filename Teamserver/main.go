package main

import "github.com/Cracked5pider/Havoc/teamserver/cmd"
import "github.com/Cracked5pider/Havoc/teamserver/pkg/logger"

func main() {
	err := cmd.TeamserverCli.Execute()
	if err != nil {
		logger.Error("Failed to execute teamserver client")
		return
	}
}
