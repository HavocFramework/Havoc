package cmd

import (
	"fmt"
	"os"
	"time"

	"Havoc/cmd/server"
	"Havoc/pkg/colors"
	"Havoc/pkg/encoder"
	"Havoc/pkg/events"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/spf13/cobra"
)

var CobraServer = &cobra.Command{
	Use:          "server",
	Short:        "teamserver command",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			DirPath, _  = os.Getwd()
			DefaultPath = DirPath + "/data/havoc.yaotl"
			ServerTimer = time.Now()
			LogrPath    = "data/loot/" + ServerTimer.Format("2006.01.02._15:04:05")
			Server      *server.Teamserver
		)

		if len(os.Args) <= 2 {
			err := cmd.Help()
			if err != nil {
				return err
			}
			os.Exit(0)
		}

		Server = server.NewTeamserver(DatabasePath)
		Server.SetServerFlags(flags)

		if flags.Server.Default {
			encoder.Initialize(DefaultPath)
			if Server.Flags.Server.Password && encoder.FileEncrypted(DefaultPath) {
				encoder.ChangePassword(DefaultPath)
			}
		} else if flags.Server.Profile != "" {
			encoder.Initialize(flags.Server.Profile)
			if Server.Flags.Server.Password && encoder.FileEncrypted(flags.Server.Profile) {
				encoder.ChangePassword(flags.Server.Profile)
			}
		}

		logr.LogrInstance = logr.NewLogr(DirPath, LogrPath)
		if logr.LogrInstance == nil {
			logger.Error("failed to create logr loot folder")
			return nil
		}

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
			Server.SetProfile(DefaultPath)
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

		// start teamserver
		Server.Start()

		os.Exit(0)

		return nil
	},
}
