package logger

import (
    "fmt"
    "log"
    "os"
    "runtime"
    "strconv"
    "strings"
    "time"

    "Havoc/pkg/colors"
)

func FunctionTrace() (string, int) {
    var (
        frame    runtime.Frame
        frames   *runtime.Frames
        caller   = make([]uintptr, 15)
        callNums int
    )

    callNums = runtime.Callers(2, caller)

    frames = runtime.CallersFrames(caller[:callNums])

    frame, _ = frames.Next()
    frame, _ = frames.Next()
    frame, _ = frames.Next()

    return frame.Function, frame.Line
}

type Logger struct {
    STDOUT *os.File
    STDERR *os.File

    log      *log.Logger
    showTime bool
    debug    bool
}

func (logger *Logger) Info(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.Blue("INFO") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.Blue("INFO") + "] ")
    }
    logger.log.Println(args...)
}

func (logger *Logger) Good(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.Green("GOOD") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.Green("GOOD") + "] ")
    }
    logger.log.Println(args...)
}

func (logger *Logger) Debug(args ...interface{}) {
    var Trace, Line = FunctionTrace()
    var Functions = strings.Split(Trace, "/")
    if logger.debug {
        if logger.showTime {
            logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.Yellow("DBUG") + "] [" + colors.BlueUnderline(Functions[len(Functions)-1]+":"+strconv.Itoa(Line)) + "]: ")
        } else {
            logger.log.SetPrefix("[" + colors.Yellow("DBUG") + "] [" + Functions[len(Functions)-1] + ":" + fmt.Sprintf("%03d", Line) + "]: ")
        }
        logger.log.Println(args...)
    }
}

func (logger *Logger) DebugError(args ...interface{}) {
    var Trace, Line = FunctionTrace()
    var Functions = strings.Split(Trace, "/")
    if logger.debug {
        if logger.showTime {
            logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.BoldRed("DBER") + "] [" + colors.BlueUnderline(Functions[len(Functions)-1]+":"+strconv.Itoa(Line)) + "]: ")
        } else {
            logger.log.SetPrefix("[" + colors.BoldRed("DBER") + "] [" + Functions[len(Functions)-1] + ":" + fmt.Sprintf("%03d", Line) + "]: ")
        }
        logger.log.Println(args...)
    }
}

func (logger *Logger) Warn(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.Yellow("WARN") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.Yellow("WARN") + "] ")
    }
    logger.log.Println(args...)
}

func (logger *Logger) Error(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.Red("ERRO") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.Red("ERRO") + "] ")
    }
    logger.log.Println(args...)
}

func (logger *Logger) Fatal(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.BoldRed("FATA") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.BoldRed("FATA") + "] ")
    }
    logger.log.Println(args...)
    os.Exit(1)
}

func (logger *Logger) Panic(args ...interface{}) {
    if logger.showTime {
        logger.log.SetPrefix("[" + colors.Green(time.Now().Format("15:04:05")) + "] [" + colors.BoldRed("PANIC") + "] ")
    } else {
        logger.log.SetPrefix("[" + colors.BoldRed("PANIC") + "] ")
    }
    logger.log.Println(args...)
    panic(args)
}

func (logger *Logger) SetDebug(enable bool) {
    logger.debug = enable
}

func (logger *Logger) ShowTime(time bool) {
    logger.showTime = time
}
