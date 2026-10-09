// SPDX-License-Identifier: MIT

// Package logx is how the library writes its log entries: a constant message
// plus key-value fields. They go to the application's logger as structured
// fields when it implements iec104.FieldLogger, and as one formatted line
// otherwise.
package logx

import (
	"context"
	"fmt"
	"strings"

	iec104 "github.com/otfabric/go-iec104"
)

// Logger writes entries of one component. A nil *Logger discards everything,
// so call sites need no nil checks.
type Logger struct {
	base   iec104.Logger
	fields iec104.FieldLogger   // base with the component fields, when structured
	ctx    iec104.ContextLogger // base, when context-aware
	static []any                // component fields, for the context path
	prefix string               // for the formatted path
	debug  func() bool
}

// New returns a logger for a component ("client", "server"). kv are fields
// every entry of the component carries. A nil base returns nil.
func New(base iec104.Logger, component string, kv ...any) *Logger {
	if base == nil {
		return nil
	}
	l := &Logger{base: base, prefix: "iec104 " + component}
	l.static = append([]any{"component", "iec104." + component}, kv...)
	if fl, ok := base.(iec104.FieldLogger); ok {
		l.fields = fl.With(l.static...)
	}
	l.ctx, _ = base.(iec104.ContextLogger)
	if d, ok := base.(interface{ DebugEnabled() bool }); ok {
		l.debug = d.DebugEnabled
	}
	if len(kv) > 0 {
		l.prefix += format(kv)
	}
	return l
}

// With returns a logger that adds kv to every entry.
func (l *Logger) With(kv ...any) *Logger {
	if l == nil {
		return nil
	}
	c := *l
	c.static = append(append([]any(nil), l.static...), kv...)
	if l.fields != nil {
		c.fields = l.fields.With(kv...)
	}
	c.prefix += format(kv)
	return &c
}

// DebugEnabled reports whether a debug entry would be written. It is true
// unless the application's logger says otherwise.
func (l *Logger) DebugEnabled() bool {
	return l != nil && (l.debug == nil || l.debug())
}

// format renders fields as " key=value ...".
func format(kv []any) string {
	var sb strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&sb, " %v=%v", kv[i], kv[i+1])
	}
	return sb.String()
}

func (l *Logger) line(msg string, kv []any) string {
	return l.prefix + ": " + msg + format(kv)
}

// Debug writes a debug entry.
func (l *Logger) Debug(msg string, kv ...any) {
	switch {
	case l == nil:
	case l.fields != nil:
		l.fields.DebugKV(msg, kv...)
	default:
		l.base.Debugf("%s", l.line(msg, kv))
	}
}

// Info writes an informational entry.
func (l *Logger) Info(msg string, kv ...any) {
	switch {
	case l == nil:
	case l.fields != nil:
		l.fields.InfoKV(msg, kv...)
	default:
		l.base.Infof("%s", l.line(msg, kv))
	}
}

// Warn writes a warning.
func (l *Logger) Warn(msg string, kv ...any) {
	switch {
	case l == nil:
	case l.fields != nil:
		l.fields.WarnKV(msg, kv...)
	default:
		l.base.Warnf("%s", l.line(msg, kv))
	}
}

// Error writes an error entry.
func (l *Logger) Error(msg string, kv ...any) {
	switch {
	case l == nil:
	case l.fields != nil:
		l.fields.ErrorKV(msg, kv...)
	default:
		l.base.Errorf("%s", l.line(msg, kv))
	}
}

// DebugContext writes a debug entry that belongs to the request ctx came
// with, through the application's ContextLogger when it has one.
func (l *Logger) DebugContext(ctx context.Context, msg string, kv ...any) {
	if l == nil {
		return
	}
	if l.ctx != nil {
		l.ctx.DebugContext(ctx, msg, append(append([]any(nil), l.static...), kv...)...)
		return
	}
	l.Debug(msg, kv...)
}

// WarnContext is the warning counterpart of DebugContext.
func (l *Logger) WarnContext(ctx context.Context, msg string, kv ...any) {
	if l == nil {
		return
	}
	if l.ctx != nil {
		l.ctx.WarnContext(ctx, msg, append(append([]any(nil), l.static...), kv...)...)
		return
	}
	l.Warn(msg, kv...)
}
