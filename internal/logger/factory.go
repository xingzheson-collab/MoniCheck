package logger

import (
	"io"
	"log/slog"
	"strings"
)

func New(out io.Writer, level string) Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	case "quiet":
		slogLevel = slog.Level(100)
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slogLevel})
	return &slogLogger{base: slog.New(handler)}
}
