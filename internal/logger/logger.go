package logger

import (
	"context"
	"log/slog"
)

type Logger interface {
	Info(ctx context.Context, msg string, fields ...any)
	Error(ctx context.Context, msg string, fields ...any)
	Debug(ctx context.Context, msg string, fields ...any)
}

type slogLogger struct {
	base *slog.Logger
}

func (l *slogLogger) Info(ctx context.Context, msg string, fields ...any) {
	l.base.InfoContext(ctx, msg, fields...)
}

func (l *slogLogger) Error(ctx context.Context, msg string, fields ...any) {
	l.base.ErrorContext(ctx, msg, fields...)
}

func (l *slogLogger) Debug(ctx context.Context, msg string, fields ...any) {
	l.base.DebugContext(ctx, msg, fields...)
}
