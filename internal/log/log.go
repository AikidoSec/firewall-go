package log

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var (
	levelVar  slog.LevelVar
	logger    *slog.Logger
	logWriter = os.Stdout
	logFormat = "text" // "text" or "json"
)

func rebuildLogger() {
	var handler slog.Handler
	if logFormat == "json" {
		handler = slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: &levelVar})
	} else {
		handler = slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: &levelVar})
	}

	SetLogger(slog.New(handler))
}

func init() {
	levelVar.Set(slog.LevelInfo)
	rebuildLogger()
}

func logMessage(level LogLevel, msg string, args ...any) {
	slogLevel := toSlogLevel(level)
	logger.Log(context.Background(), slogLevel, msg, args...)
}

func Debug(msg string, args ...any) {
	logMessage(DebugLevel, msg, args...)
}

func Info(msg string, args ...any) {
	logMessage(InfoLevel, msg, args...)
}

func Warn(msg string, args ...any) {
	logMessage(WarnLevel, msg, args...)
}

func Error(msg string, args ...any) {
	logMessage(ErrorLevel, msg, args...)
}

func SetLogLevel(level string) error {
	normalized := strings.ToUpper(strings.TrimSpace(level))
	switch normalized {
	case "DEBUG":
		levelVar.Set(slog.LevelDebug)
	case "INFO":
		levelVar.Set(slog.LevelInfo)
	case "WARN", "WARNING":
		levelVar.Set(slog.LevelWarn)
	case "ERROR", "ERR":
		levelVar.Set(slog.LevelError)
	default:
		return errors.New("invalid log level")
	}
	return nil
}

// SetLogger allows consumers to supply their own slog.Logger. When provided,
// the internal logger will use it as-is (including its handler, writer, level).
// SetLogLevel will still update levelVar for the default logger, but will not
// override a custom logger's handler configuration.
func SetLogger(l *slog.Logger) {
	if l == nil {
		return
	}
	logger = l.With(slog.String("lib", "aikido"))
}

// Logger returns the currently in-use instance of *slog.Logger
// This can be used in tests to get the default loggers to later restore on cleanup.
func Logger() *slog.Logger {
	return logger
}

func SetFormat(format string) error {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "text", "console":
		logFormat = "text"
	case "json":
		logFormat = "json"
	default:
		return errors.New("invalid log format")
	}
	rebuildLogger()
	return nil
}

func toSlogLevel(level LogLevel) slog.Level {
	switch level {
	case DebugLevel:
		return slog.LevelDebug
	case InfoLevel:
		return slog.LevelInfo
	case WarnLevel:
		return slog.LevelWarn
	case ErrorLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
