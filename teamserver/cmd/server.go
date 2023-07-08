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
			ProfilePath string
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
			ProfilePath = DirPath + "/data/havoc.yaotl"
		} else {
			ProfilePath = flags.Server.Profile
		}
		encoder.Initialize(ProfilePath)
		if Server.Flags.Server.UpdatePass && encoder.FileEncrypted(ProfilePath) {
			encoder.ChangePassword(ProfilePath)
		}

		if Server.Flags.Server.Decrypt && encoder.FileEncrypted(ProfilePath) {
			encoder.EncoderInstance.Decrypt = true
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

		Server.SetProfile(ProfilePath)

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
