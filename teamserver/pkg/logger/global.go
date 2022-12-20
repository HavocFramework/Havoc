package logger

import (
    "io"
    "log"
    "os"
)

var LoggerInstance *Logger

func init() {
    LoggerInstance = NewLogger(os.Stdout)
}

func NewLogger(StdOut io.Writer) *Logger {
    var logger = new(Logger)

    logger.STDOUT = os.Stdout
    logger.STDERR = os.Stderr
    logger.showTime = true
    logger.debug = false
    logger.log = log.New(StdOut, "", 0)

    return logger
}

func Info(args ...interface{}) {
    LoggerInstance.Info(args...)
}

func Good(args ...interface{}) {
    LoggerInstance.Good(args...)
}

func Debug(args ...interface{}) {
    LoggerInstance.Debug(args...)
}

func DebugError(args ...interface{}) {
    LoggerInstance.DebugError(args...)
}

func Warn(args ...interface{}) {
    LoggerInstance.Warn(args...)
}

func Error(args ...interface{}) {
    LoggerInstance.Error(args...)
}

func Fatal(args ...interface{}) {
    LoggerInstance.Fatal(args...)
}

func Panic(args ...interface{}) {
    LoggerInstance.Panic(args...)
}

func SetDebug(enable bool) {
    LoggerInstance.SetDebug(enable)
}

func ShowTime(time bool) {
    LoggerInstance.ShowTime(time)
}

func SetStdOut(w io.Writer) {
    LoggerInstance.log.SetOutput(w)
}
