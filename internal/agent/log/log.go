package log

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/globals"
)

const (
	DebugLevel int32 = 0
	InfoLevel  int32 = 1
	WarnLevel  int32 = 2
	ErrorLevel int32 = 3
)

var (
	currentLogLevel int32 = ErrorLevel
	logger                = log.New(os.Stdout, "", 0)
	cliLogging            = false
	logFile         *os.File
)

type AikidoFormatter struct{}

func (f *AikidoFormatter) Format(level int32, message string) string {
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

	logMessage := fmt.Sprintf("[AIKIDO][%s][%s] %s\n", levelStr, time.Now().Format("15:04:05"), message)
	return logMessage
}

func logMessage(level int32, args ...any) {
	if level >= atomic.LoadInt32(&currentLogLevel) {
		formatter := &AikidoFormatter{}
		message := fmt.Sprint(args...)
		formattedMessage := formatter.Format(level, message)
		logger.Print(formattedMessage)
	}
}

func logMessagef(level int32, format string, args ...any) {
	if level >= atomic.LoadInt32(&currentLogLevel) {
		formatter := &AikidoFormatter{}
		message := fmt.Sprintf(format, args...)
		formattedMessage := formatter.Format(level, message)
		logger.Print(formattedMessage)
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
	var levelInt int32
	switch level {
	case "DEBUG":
		levelInt = DebugLevel
	case "INFO":
		levelInt = InfoLevel
	case "WARN":
		levelInt = WarnLevel
	case "ERROR":
		levelInt = ErrorLevel
	default:
		return errors.New("invalid log level")
	}
	atomic.StoreInt32(&currentLogLevel, levelInt)
	return nil
}

func Init() {
	currentTime := time.Now()
	timeStr := currentTime.Format("20060102150405")
	logFilePath := fmt.Sprintf(
		"/var/log/aikido-%s/aikido-agent-%s-%d.log",
		globals.EnvironmentConfig.Version, timeStr, os.Getpid())

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		// /var/log directory is optional except for firewall-php :
		if globals.EnvironmentConfig.Library == "firewall-php" {
			log.Fatalf("Failed to open log file: %v", err)
		}
		cliLogging = true // Turn cli logging on if the log file creation fails.
		Debugf("Failed to open log file: %v", err)
	} else {
		logger.SetOutput(logFile)
	}
}

func Uninit() error {
	logger.SetOutput(os.Stdout)

	if err := logFile.Close(); err != nil {
		return err
	}

	return nil
}
