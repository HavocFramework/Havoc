package cmd

import (
    "fmt"
    "os"

    "Havoc/pkg/colors"
    "Havoc/pkg/teamserver"

    "github.com/spf13/cobra"
)

var (
    TeamserverCli = &cobra.Command{
        Use:          "teamserver",
        Short:        "Havoc Teamserver",
        SilenceUsage: true,
        RunE:         teamserverFunc,
    }

    flags teamserver.TeamserverFlags
)

func init() {
    TeamserverCli.CompletionOptions.DisableDefaultCmd = true
    TeamserverCli.AddCommand(ServerCli)
}

func teamserverFunc(cmd *cobra.Command, args []string) error {
    startMenu()

    if len(os.Args) <= 2 {
        err := cmd.Help()
        if err != nil {
            return err
        }
        os.Exit(0)
    }

    return nil
}

func startMenu() {
    fmt.Println(colors.Red("              _______           _______  _______ \n    │\\     /│(  ___  )│\\     /│(  ___  )(  ____ \\\n    │ )   ( ││ (   ) ││ )   ( ││ (   ) ││ (    \\/\n    │ (___) ││ (___) ││ │   │ ││ │   │ ││ │      \n    │  ___  ││  ___  │( (   ) )│ │   │ ││ │      \n    │ (   ) ││ (   ) │ \\ \\_/ / │ │   │ ││ │      \n    │ )   ( ││ )   ( │  \\   /  │ (___) ││ (____/\\\n    │/     \\││/     \\│   \\_/   (_______)(_______/"))
    fmt.Println()
    fmt.Println("  	", colors.Red("pwn"), "and", colors.Blue("elevate"), "until it's done")
    fmt.Println()
}
