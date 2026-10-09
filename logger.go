// SPDX-License-Identifier: MIT

package iec104

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
)

// Logger is the logging interface accepted by the client and the server.
// Implement it to integrate any logging library.
//
// Logging is silent by default. Methods are invoked synchronously on the
// protocol path and must not block.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// NopLogger returns a Logger that discards everything.
func NopLogger() Logger { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// NewStdLogger wraps a standard library logger. Each message is prefixed
// with its level. A nil l logs to os.Stderr with the standard flags.
func NewStdLogger(l *log.Logger) Logger {
	if l == nil {
		l = log.New(os.Stderr, "", log.LstdFlags)
	}
	return stdLogger{l}
}

type stdLogger struct{ l *log.Logger }

func (s stdLogger) Debugf(f string, a ...any) { s.l.Printf("DEBUG "+f, a...) }
func (s stdLogger) Infof(f string, a ...any)  { s.l.Printf("INFO  "+f, a...) }
func (s stdLogger) Warnf(f string, a ...any)  { s.l.Printf("WARN  "+f, a...) }
func (s stdLogger) Errorf(f string, a ...any) { s.l.Printf("ERROR "+f, a...) }

// FieldLogger extends [Logger] with structured key-value logging. When the
// Logger given to a client or server also implements FieldLogger, the library
// logs through it: every entry is a constant message plus fields such as
// "component", "remote", "state", "type", "cause" and "error", instead of one
// formatted string. [NewSlogLogger] returns such a logger.
//
// keysAndValues alternate string keys and values, as in log/slog.
type FieldLogger interface {
	Logger

	// With returns a logger that adds the given fields to every entry.
	With(keysAndValues ...any) FieldLogger

	DebugKV(msg string, keysAndValues ...any)
	InfoKV(msg string, keysAndValues ...any)
	WarnKV(msg string, keysAndValues ...any)
	ErrorKV(msg string, keysAndValues ...any)
}

// ContextLogger extends [Logger] with context-aware structured logging, so
// that a handler can pick trace and span identifiers out of the context.
// When the Logger also implements ContextLogger, entries that belong to a
// request are logged with the context the request was called with.
type ContextLogger interface {
	Logger

	DebugContext(ctx context.Context, msg string, keysAndValues ...any)
	InfoContext(ctx context.Context, msg string, keysAndValues ...any)
	WarnContext(ctx context.Context, msg string, keysAndValues ...any)
	ErrorContext(ctx context.Context, msg string, keysAndValues ...any)
}

// NewSlogLogger wraps a slog.Handler. The result implements [FieldLogger] and
// [ContextLogger], so the library logs structured fields through it; messages
// are only built when the handler is enabled for their level. A nil handler
// returns a no-op logger.
func NewSlogLogger(h slog.Handler) Logger {
	if h == nil {
		return nopLogger{}
	}
	return &slogLogger{h: h, l: slog.New(h)}
}

// NewSlogFieldLogger is [NewSlogLogger] with the result typed as a
// [FieldLogger], for callers that want to add fields with With before handing
// the logger to a client or server. A nil handler returns a no-op logger.
func NewSlogFieldLogger(h slog.Handler) FieldLogger {
	if h == nil {
		return nopFieldLogger{}
	}
	return &slogLogger{h: h, l: slog.New(h)}
}

type nopFieldLogger struct{ nopLogger }

func (n nopFieldLogger) With(...any) FieldLogger { return n }
func (nopFieldLogger) DebugKV(string, ...any)    {}
func (nopFieldLogger) InfoKV(string, ...any)     {}
func (nopFieldLogger) WarnKV(string, ...any)     {}
func (nopFieldLogger) ErrorKV(string, ...any)    {}

type slogLogger struct {
	h slog.Handler
	l *slog.Logger
}

func (s *slogLogger) logf(level slog.Level, f string, a []any) {
	if s.h.Enabled(context.Background(), level) {
		s.l.Log(context.Background(), level, fmt.Sprintf(f, a...))
	}
}

func (s *slogLogger) Debugf(f string, a ...any) { s.logf(slog.LevelDebug, f, a) }
func (s *slogLogger) Infof(f string, a ...any)  { s.logf(slog.LevelInfo, f, a) }
func (s *slogLogger) Warnf(f string, a ...any)  { s.logf(slog.LevelWarn, f, a) }
func (s *slogLogger) Errorf(f string, a ...any) { s.logf(slog.LevelError, f, a) }

func (s *slogLogger) With(kv ...any) FieldLogger {
	l := s.l.With(kv...)
	return &slogLogger{h: l.Handler(), l: l}
}

func (s *slogLogger) DebugKV(msg string, kv ...any) { s.l.Debug(msg, kv...) }
func (s *slogLogger) InfoKV(msg string, kv ...any)  { s.l.Info(msg, kv...) }
func (s *slogLogger) WarnKV(msg string, kv ...any)  { s.l.Warn(msg, kv...) }
func (s *slogLogger) ErrorKV(msg string, kv ...any) { s.l.Error(msg, kv...) }

func (s *slogLogger) DebugContext(ctx context.Context, msg string, kv ...any) {
	s.l.DebugContext(ctx, msg, kv...)
}
func (s *slogLogger) InfoContext(ctx context.Context, msg string, kv ...any) {
	s.l.InfoContext(ctx, msg, kv...)
}
func (s *slogLogger) WarnContext(ctx context.Context, msg string, kv ...any) {
	s.l.WarnContext(ctx, msg, kv...)
}
func (s *slogLogger) ErrorContext(ctx context.Context, msg string, kv ...any) {
	s.l.ErrorContext(ctx, msg, kv...)
}

// DebugEnabled reports whether the handler takes debug entries. The library
// uses it to skip building per-frame entries nobody will see.
func (s *slogLogger) DebugEnabled() bool { return s.h.Enabled(context.Background(), slog.LevelDebug) }
