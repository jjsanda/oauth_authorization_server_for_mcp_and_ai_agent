package httpx

import (
	"log/slog"
	"os"
)

// NewLogger builds a slog logger from a level name ("debug".."error", falling
// back to info) and a format ("json" for structured output, anything else for
// text). Used by every server binary so logging is configured identically.
func NewLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
