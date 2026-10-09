// SPDX-License-Identifier: MIT

package iec104

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/otfabric/go-iec104/apci"
	"github.com/otfabric/go-iec104/asdu"
)

func TestState(t *testing.T) {
	for s, want := range map[State]string{
		StateDisconnected: "disconnected", StateConnecting: "connecting",
		StateStopped: "stopped", StateStarted: "started", 9: "unknown",
	} {
		if s.String() != want {
			t.Errorf("State(%d) = %q, want %q", s, s.String(), want)
		}
	}
}

func TestNegativeError(t *testing.T) {
	var err error = &NegativeError{ASDU: &asdu.ASDU{Type: asdu.C_SC_NA_1, Cause: asdu.CauseUnknownIOA, CommonAddr: 7, Negative: true}}
	var neg *NegativeError
	if !errors.As(err, &neg) || neg.Cause() != asdu.CauseUnknownIOA {
		t.Fatalf("errors.As / Cause: %v", err)
	}
	if got, want := err.Error(), "iec104: C_SC_NA_1 rejected by station 7: unknown-ioa"; got != want {
		t.Errorf("Error = %q, want %q", got, want)
	}
	empty := &NegativeError{}
	if empty.Cause() != 0 || empty.Error() == "" {
		t.Error("NegativeError without ASDU")
	}
}

func TestLoggers(t *testing.T) {
	exercise := func(l Logger) {
		l.Debugf("d %d", 1)
		l.Infof("i %d", 2)
		l.Warnf("w %d", 3)
		l.Errorf("e %d", 4)
	}
	exercise(NopLogger())
	exercise(NewSlogLogger(nil))

	var std bytes.Buffer
	exercise(NewStdLogger(log.New(&std, "", 0)))
	if got, want := std.String(), "DEBUG d 1\nINFO  i 2\nWARN  w 3\nERROR e 4\n"; got != want {
		t.Errorf("std logger wrote %q, want %q", got, want)
	}
	if NewStdLogger(nil) == nil {
		t.Error("NewStdLogger(nil)")
	}

	var sl bytes.Buffer
	exercise(NewSlogLogger(slog.NewTextHandler(&sl, &slog.HandlerOptions{Level: slog.LevelInfo})))
	out := sl.String()
	if strings.Contains(out, "d 1") {
		t.Error("slog logger ignored the handler level")
	}
	for _, want := range []string{`level=INFO msg="i 2"`, `level=WARN msg="w 3"`, `level=ERROR msg="e 4"`} {
		if !strings.Contains(out, want) {
			t.Errorf("slog output misses %s:\n%s", want, out)
		}
	}
}

func TestNopMetrics(t *testing.T) {
	var m Metrics = NopMetrics{}
	m.OnConnect(nil)
	m.OnDisconnect(nil, nil)
	m.OnFrameSent(nil, apci.Frame{}, 0)
	m.OnFrameReceived(nil, apci.Frame{}, 0)
	m.OnDecodeError(nil, nil)
}

func TestStructuredLoggers(t *testing.T) {
	var buf bytes.Buffer
	fl := NewSlogFieldLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fl = fl.With("site", "north")
	fl.DebugKV("d", "k", 1)
	fl.InfoKV("i", "k", 2)
	fl.WarnKV("w", "k", 3)
	fl.ErrorKV("e", "k", 4)
	fl.Infof("formatted %d", 5)
	cl, ok := fl.(ContextLogger)
	if !ok {
		t.Fatal("the slog logger does not implement ContextLogger")
	}
	ctx := context.Background()
	cl.DebugContext(ctx, "cd", "k", 6)
	cl.InfoContext(ctx, "ci", "k", 7)
	cl.WarnContext(ctx, "cw", "k", 8)
	cl.ErrorContext(ctx, "ce", "k", 9)
	out := buf.String()
	for _, want := range []string{
		"level=DEBUG msg=d site=north k=1", "level=INFO msg=i site=north k=2", "level=WARN msg=w site=north k=3",
		"level=ERROR msg=e site=north k=4", `msg="formatted 5" site=north`,
		"msg=cd site=north k=6", "msg=ci site=north k=7", "msg=cw site=north k=8", "msg=ce site=north k=9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("structured output misses %q:\n%s", want, out)
		}
	}
	// NewSlogLogger is structured too.
	if _, ok := NewSlogLogger(slog.NewTextHandler(&buf, nil)).(FieldLogger); !ok {
		t.Error("NewSlogLogger does not return a FieldLogger")
	}
	if d, ok := NewSlogLogger(slog.NewTextHandler(&buf, nil)).(interface{ DebugEnabled() bool }); !ok || d.DebugEnabled() {
		t.Error("DebugEnabled at info level")
	}

	nop := NewSlogFieldLogger(nil)
	nop.With("a", 1).DebugKV("x")
	nop.InfoKV("x")
	nop.WarnKV("x")
	nop.ErrorKV("x")
	nop.Infof("x")
}
