package log

import (
	"errors"
	"fmt"
	"log"
	"os"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var (
	currentLogLevel = ErrorLevel
	Logger          = log.New(os.Stdout, "", 0)
)

type AikidoFormatter struct{}

func (f *AikidoFormatter) Format(level Level, message string) string {
	var levelStr string
	switch level {
	case DebugLevel:
		levelStr = "DEBUG"
	case InfoLevel:
		levelStr = "INFO"
	case WarnLevel:
		levelStr = "WARN"
	case ErrorLevel:
		levelStr = "ERROR"
	default:
		return "invalid log level"
	}

	return fmt.Sprintf("[AIKIDO][%s] %s\n", levelStr, message)
}

func logMessage(level Level, args ...interface{}) {
	if level >= currentLogLevel {
		formatter := &AikidoFormatter{}
		message := fmt.Sprint(args...)
		formattedMessage := formatter.Format(level, message)
		Logger.Print(formattedMessage)
	}
}

func logMessagef(level Level, format string, args ...interface{}) {
	if level >= currentLogLevel {
		formatter := &AikidoFormatter{}
		message := fmt.Sprintf(format, args...)
		formattedMessage := formatter.Format(level, message)
		Logger.Print(formattedMessage)
	}
}

func Debug(args ...interface{}) {
	logMessage(DebugLevel, args...)
}

func Info(args ...interface{}) {
	logMessage(InfoLevel, args...)
}

func Warn(args ...interface{}) {
	logMessage(WarnLevel, args...)
}

func Error(args ...interface{}) {
	logMessage(ErrorLevel, args...)
}

func Debugf(format string, args ...interface{}) {
	logMessagef(DebugLevel, format, args...)
}

func Infof(format string, args ...interface{}) {
	logMessagef(InfoLevel, format, args...)
}

func Warnf(format string, args ...interface{}) {
	logMessagef(WarnLevel, format, args...)
}

func Errorf(format string, args ...interface{}) {
	logMessagef(ErrorLevel, format, args...)

}

func SetLogLevel(level string) error {
	switch level {
	case "DEBUG":
		currentLogLevel = DebugLevel
	case "INFO":
		currentLogLevel = InfoLevel
	case "WARN":
		currentLogLevel = WarnLevel
	case "ERROR":
		currentLogLevel = ErrorLevel
	default:
		return errors.New("invalid log level")
	}
	return nil
}
