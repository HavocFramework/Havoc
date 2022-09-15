package main

import "Havoc/cmd"
import "Havoc/pkg/logger"

func main() {
    err := cmd.TeamserverCli.Execute()
    if err != nil {
        logger.Error("Failed to execute teamserver client")
        return
    }
}
