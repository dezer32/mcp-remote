// Package logging — обёртка над log/slog. Лог всегда в stderr, чтобы stdout оставался
// чистым каналом JSON-RPC.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// New возвращает *slog.Logger в stderr.
// silent имеет приоритет над debug: silent → Error+, debug → Debug, иначе Info.
func New(debug, silent bool) *slog.Logger {
	level := slog.LevelInfo
	switch {
	case silent:
		level = slog.LevelError
	case debug:
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}

// Discard возвращает no-op логгер (для тестов).
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
