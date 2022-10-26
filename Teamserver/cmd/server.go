package cmd

import (
    "Havoc/pkg/events"
    "fmt"
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

    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.Debug, "debug", "", false, "enable debug mode")
    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.DebugDev, "debug-dev", "", false, "enable debug mode for developers (compiles the agent with the debug mode/macro enabled)")
    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.Default, "default", "d", false, "uses default profile (overwrites --profile)")
    ServerCli.Flags().BoolVarP(&teamserverFlags.Server.Verbose, "verbose", "v", false, "verbose messages")
}

func serverFunc(cmd *cobra.Command, args []string) error {
    var DirPath, _ = os.Getwd()

    if len(os.Args) <= 2 {
        err := cmd.Help()
        if err != nil {
            return err
        }
        os.Exit(0)
    }

    teamserver.HavocTeamserver = teamserver.NewTeamserver()
    teamserver.HavocTeamserver.SetServerFlags(teamserverFlags)

    logr.LogrInstance = logr.NewLogr(DirPath + "/data/loot")
    logr.LogrInstance.LogrSendText = func(text string) {
        var pk = events.Teamserver.Logger(text)

        teamserver.HavocTeamserver.EventAppend(pk)
        teamserver.HavocTeamserver.EventBroadcast("", pk)
    }

    logr.LogrInstance.ServerStdOutInit()

    startMenu()

    if teamserverFlags.Server.Debug {
        logger.SetDebug(true)
        logger.Debug("Debug mode enabled")
    }

    logger.ShowTime(teamserverFlags.Server.Verbose)

    logger.Info(fmt.Sprintf("Havoc Framework [Version: %v] [CodeName: %v]", VersionNumber, VersionName))
    if teamserverFlags.Server.Default {
        teamserver.HavocTeamserver.SetProfile(DirPath + "/data/havoc.yaotl")
    } else if teamserverFlags.Server.Profile != "" {
        teamserver.HavocTeamserver.SetProfile(teamserverFlags.Server.Profile)
    } else {
        logger.Error("No profile specified. Specify a profile with --profile or choose the standard profile with --default")
        os.Exit(1)
    }

    if !teamserver.HavocTeamserver.FindSystemPackages() {
        logger.Error("Please install needed packages. Refer to the Wiki for more help.")
        os.Exit(1)
    }

    teamserver.HavocTeamserver.Start()

    return nil
}
