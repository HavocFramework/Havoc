package logr

import (
    "os"

    "Havoc/pkg/logger"
)

type Logr struct {
    // Path to directory where everything is going to be logged (user chat, input/output from agent)
    Path         string
    ListenerPath string
    AgentPath    string
}

var LogrInstance *Logr

func NewLogr(Path string) *Logr {
    var (
        logr = new(Logr)
        err  error
    )

    logr.Path = Path
    logr.ListenerPath = Path + "/listener"
    logr.AgentPath = Path + "/agents"

    if _, err = os.Stat(Path); os.IsNotExist(err) {
        if err = os.Mkdir(Path, os.ModePerm); err != nil {
            logger.Error("Failed to create Logr folder: " + err.Error())
            return nil
        }
    } else {
        err = os.RemoveAll(Path)
        if err == nil {
            if err = os.Mkdir(Path, os.ModePerm); err != nil {
                logger.Error("Failed to create Logr folder: " + err.Error())
                return nil
            }
        } else {
            logger.Error(err.Error())
        }
    }

    if _, err = os.Stat(logr.AgentPath); os.IsNotExist(err) {
        if err = os.Mkdir(logr.AgentPath, os.ModePerm); err != nil {
            logger.Error("Failed to create Logr agent folder: " + err.Error())
            return nil
        }
    }

    if _, err = os.Stat(logr.ListenerPath); os.IsNotExist(err) {
        if err = os.Mkdir(logr.ListenerPath, os.ModePerm); err != nil {
            logger.Error("Failed to create Logr listener folder: " + err.Error())
            return nil
        }
    }

    return logr
}
