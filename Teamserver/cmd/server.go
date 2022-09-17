package cmd

import (
    "io"
    "log"
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

func logOutput() func() {
    logfile := `logfile`
    // open file read/write | create if not exist | clear file at open if exists
    f, _ := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

    // save existing stdout | MultiWriter writes to saved stdout and file
    out := os.Stdout
    mw := io.MultiWriter(out, f)

    // get pipe reader and writer | writes to pipe writer come out pipe reader
    r, w, _ := os.Pipe()

    // replace stdout,stderr with pipe writer | all writes to stdout, stderr will go through pipe instead (fmt.print, log)
    os.Stdout = w
    os.Stderr = w

    // writes with log.Print should also write to mw
    log.SetOutput(mw)

    //create channel to control exit | will block until all copies are finished
    exit := make(chan bool)

    go func() {
        // copy all reads from pipe to multiwriter, which writes to stdout and file
        _, _ = io.Copy(mw, r)
        // when r or w is closed copy will finish and true will be sent to channel
        exit <- true
    }()

    // function to be deferred in main until program exits
    return func() {
        // close writer then block on exit channel | this will let mw finish writing before the program exits
        _ = w.Close()
        <-exit
        // close file after all writes have finished
        _ = f.Close()
    }

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

        if !teamserver.HavocTeamserver.FindSystemPackages() {
            logger.Error("Install needed packages")
            os.Exit(1)
        }

    } else {
        logger.Error("No profile specified")
        os.Exit(1)
    }

    teamserver.HavocTeamserver.SetServerFlags(teamserverFlags)
    teamserver.HavocTeamserver.Start()

    return nil
}
