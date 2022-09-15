package cmd

import (
    "os"

    "Havoc/pkg/logger"
    "Havoc/pkg/logr"
    "Havoc/pkg/teamserver"
    "github.com/spf13/cobra"
)

var (
    ServerCli = &cobra.Command{
        Use:          "server",
        Short:        "server command",
        SilenceUsage: true,
        RunE:         serverFunc,
    }
)

func init() {
    ServerCli.Flags().SortFlags = false

    ServerCli.Flags().StringVarP(&teamserverFlags.Server.Profile, "profile", "", "", "set havoc teamserver profile")

    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.Verbose, "verbose", "v", false, "verbose messages")
    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.Debug, "debug", "d", false, "enable debug mode")
    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.DebugDev, "debug-dev", "", false, "enable debug mode for developers (compiles the agent with the debug mode/macro enabled)")
}

func serverFunc(cmd *cobra.Command, args []string) error {
    startMenu()

    teamserver.HavocTeamserver = teamserver.NewTeamserver()

    if len(os.Args) <= 2 {
        err := cmd.Help()
        if err != nil {
            return err
        }
        os.Exit(0)
    }

    var DirPath, _ = os.Getwd()
    logr.LogrInstance = logr.NewLogr(DirPath + "/data/loot")
    logr.LogrInstance.ServerStdOutInit()

    if !teamserver.HavocTeamserver.FindSystemPackages() {
        logger.Error("Install needed packages")
    }

    if teamserverFlags.Server.Debug {
        logger.SetDebug(true)
        logger.Debug("Debug mode enabled")
    }

    if teamserverFlags.Server.Verbose {
        logger.ShowTime(true)
    } else {
        logger.ShowTime(false)
    }

    if teamserverFlags.Server.Profile != "" {
        teamserver.HavocTeamserver.SetProfile(teamserverFlags.Server.Profile)
    } else {
        logger.Error("No profile specified")
        os.Exit(1)
    }

    teamserver.HavocTeamserver.SetServerFlags(teamserverFlags)
    teamserver.HavocTeamserver.Start()

    return nil
}
