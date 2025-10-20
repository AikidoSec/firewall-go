package log

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var (
	currentLogLevel = ErrorLevel
	Logger          = log.New(os.Stdout, "", 0)
	cliLogging      = true
)

type AikidoFormatter struct{}

func (f *AikidoFormatter) Format(level LogLevel, message string) string {
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

	if cliLogging {
		return fmt.Sprintf("[AIKIDO][%s] %s\n", levelStr, message)
	}
	return fmt.Sprintf("[AIKIDO][%s][%s] %s\n", levelStr, time.Now().Format("15:04:05"), message)
}

func logMessage(level LogLevel, args ...any) {
	if level >= currentLogLevel {
		formatter := &AikidoFormatter{}
		message := fmt.Sprint(args...)
		formattedMessage := formatter.Format(level, message)
		Logger.Print(formattedMessage)
	}
}

func logMessagef(level LogLevel, format string, args ...any) {
	if level >= currentLogLevel {
		formatter := &AikidoFormatter{}
		message := fmt.Sprintf(format, args...)
		formattedMessage := formatter.Format(level, message)
		Logger.Print(formattedMessage)
	}
}

func Debug(args ...any) {
	logMessage(DebugLevel, args...)
}

func Info(args ...any) {
	logMessage(InfoLevel, args...)
}

func Warn(args ...any) {
	logMessage(WarnLevel, args...)
}

func Error(args ...any) {
	logMessage(ErrorLevel, args...)
}

func Debugf(format string, args ...any) {
	logMessagef(DebugLevel, format, args...)
}

func Infof(format string, args ...any) {
	logMessagef(InfoLevel, format, args...)
}

func Warnf(format string, args ...any) {
	logMessagef(WarnLevel, format, args...)
}

func Errorf(format string, args ...any) {
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
