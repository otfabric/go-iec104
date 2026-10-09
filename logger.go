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

// NewSlogLogger wraps a slog.Handler. Messages are formatted only when the
// handler is enabled for their level. A nil handler returns a no-op logger.
func NewSlogLogger(h slog.Handler) Logger {
	if h == nil {
		return nopLogger{}
	}
	return slogLogger{h: h, l: slog.New(h)}
}

type slogLogger struct {
	h slog.Handler
	l *slog.Logger
}

func (s slogLogger) log(level slog.Level, f string, a []any) {
	if s.h.Enabled(context.Background(), level) {
		s.l.Log(context.Background(), level, fmt.Sprintf(f, a...))
	}
}

func (s slogLogger) Debugf(f string, a ...any) { s.log(slog.LevelDebug, f, a) }
func (s slogLogger) Infof(f string, a ...any)  { s.log(slog.LevelInfo, f, a) }
func (s slogLogger) Warnf(f string, a ...any)  { s.log(slog.LevelWarn, f, a) }
func (s slogLogger) Errorf(f string, a ...any) { s.log(slog.LevelError, f, a) }
