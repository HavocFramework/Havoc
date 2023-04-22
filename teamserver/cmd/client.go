package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"os/exec"
)

var CobraClient = &cobra.Command{
	Use:          "client",
	Short:        "client command",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		startMenu()

		client := exec.Command("client/Havoc", args...)
		client.Stdout = os.Stdout
		client.Stderr = os.Stderr

		if err := client.Run(); err != nil {
			return err
		}

		return nil
	},
}
