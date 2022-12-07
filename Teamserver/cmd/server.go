package cmd

import (
	"Havoc/pkg/colors"
	"Havoc/pkg/events"
	"fmt"
	"os"
	"time"

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

	ServerCli.Flags().StringVarP(&flags.Server.Profile, "profile", "", "", "set havoc teamserver profile")

	ServerCli.Flags().BoolVarP(&flags.Server.Debug, "debug", "", false, "enable debug mode")
	ServerCli.Flags().BoolVarP(&flags.Server.DebugDev, "debug-dev", "", false, "enable debug mode for developers (compiles the agent with the debug mode/macro enabled)")
	ServerCli.Flags().BoolVarP(&flags.Server.Default, "default", "d", false, "uses default profile (overwrites --profile)")
	ServerCli.Flags().BoolVarP(&flags.Server.Verbose, "verbose", "v", false, "verbose messages")
}

func serverFunc(cmd *cobra.Command, args []string) error {
	var (
		DirPath, _  = os.Getwd()
		ServerTimer = time.Now()
		LogrPath    = "data/loot/" + ServerTimer.Format("02.01.2006_15:04:05")
		Server      *teamserver.Teamserver
	)

	if len(os.Args) <= 2 {
		err := cmd.Help()
		if err != nil {
			return err
		}
		os.Exit(0)
	}

	Server = teamserver.NewTeamserver()
	Server.SetServerFlags(flags)

	logr.LogrInstance = logr.NewLogr(DirPath, LogrPath)
	logr.LogrInstance.LogrSendText = func(text string) {
		var pk = events.Teamserver.Logger(text)

		Server.EventAppend(pk)
		Server.EventBroadcast("", pk)
	}

	logr.LogrInstance.ServerStdOutInit()

	startMenu()

	if flags.Server.Debug {
		logger.SetDebug(true)
		logger.Debug("Debug mode enabled")
	}

	logger.ShowTime(flags.Server.Verbose)

	logger.Info(fmt.Sprintf("Havoc Framework [Version: %v] [CodeName: %v]", VersionNumber, VersionName))

	if flags.Server.Default {
		Server.SetProfile(DirPath + "/data/havoc.yaotl")
	} else if flags.Server.Profile != "" {
		Server.SetProfile(flags.Server.Profile)
	} else {
		logger.Error("No profile specified. Specify a profile with --profile or choose the standard profile with --default")
		os.Exit(1)
	}

	if !Server.FindSystemPackages() {
		logger.Error("Please install needed packages. Refer to the Wiki for more help.")
		os.Exit(1)
	}

	logger.Info("Time: " + colors.Yellow(ServerTimer.Format("02/01/2006 15:04:05")))
	logger.Info("Teamserver logs saved under: " + colors.Blue(LogrPath))

	Server.Start()

	return nil
}
