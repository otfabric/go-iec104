// SPDX-License-Identifier: MIT

// Command server is a small IEC 60870-5-104 controlled station: a handful
// of points, a switch that accepts single commands, and a measurement that
// changes every second and is reported spontaneously.
//
//	go run ./examples/server -addr :2404
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"sync"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/server"
)

const (
	station      asdu.CommonAddr = 1
	ioaSwitch    asdu.IOA        = 1001 // single point, state of the switch
	ioaFreq      asdu.IOA        = 4001 // measured value, frequency in Hz
	ioaSwitchCmd asdu.IOA        = 6001 // single command operating the switch
)

type process struct {
	mu     sync.Mutex
	closed bool
	freq   float32
}

func (p *process) snapshot() (bool, float32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed, p.freq
}

func main() {
	addr := flag.String("addr", ":2404", "listen address")
	debug := flag.Bool("debug", false, "log every APDU")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := iec104.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	proc := &process{freq: 50}
	mux := server.NewMux()

	// General interrogation: confirm, report every point, terminate.
	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
		qoi := req.First().(asdu.Interrogation).Qualifier
		if qoi != asdu.QOIStation {
			_ = s.Negative(req)
			return
		}
		closed, freq := proc.snapshot()
		_ = s.Confirm(req)
		_ = s.Send(s.Context(), asdu.New(qoi.Cause(), station, asdu.SinglePoint{IOA: ioaSwitch, Value: closed}))
		_ = s.Send(s.Context(), asdu.New(qoi.Cause(), station, asdu.MeasuredFloat{IOA: ioaFreq, Value: freq}))
		_ = s.Terminate(req)
	})

	mux.HandleFunc(asdu.C_CS_NA_1, func(s *server.Session, req *asdu.ASDU) {
		log.Printf("clock synchronization: %s", req.First().(asdu.ClockSync).Time.Time)
		_ = s.Confirm(req)
	})

	mux.HandleFunc(asdu.C_RD_NA_1, func(s *server.Session, req *asdu.ASDU) {
		closed, freq := proc.snapshot()
		switch req.First().Address() {
		case ioaSwitch:
			_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, station, asdu.SinglePoint{IOA: ioaSwitch, Value: closed}))
		case ioaFreq:
			_ = s.Send(s.Context(), asdu.New(asdu.CauseRequest, station, asdu.MeasuredFloat{IOA: ioaFreq, Value: freq}))
		default:
			_ = s.Reject(req, asdu.CauseUnknownIOA)
		}
	})

	var srv *server.Server
	command := func(s *server.Session, req *asdu.ASDU) {
		cmd := req.First().(asdu.SingleCommand)
		if cmd.IOA != ioaSwitchCmd {
			_ = s.Reject(req, asdu.CauseUnknownIOA)
			return
		}
		_ = s.Confirm(req)
		if cmd.Select || req.Cause == asdu.CauseDeactivation {
			return
		}
		proc.mu.Lock()
		proc.closed = cmd.Value
		proc.mu.Unlock()
		log.Printf("switch operated by %s: closed=%v", s.RemoteAddr(), cmd.Value)
		_ = s.Terminate(req)
		// Every connected control centre learns about the new state.
		_, _ = srv.Broadcast(s.Context(), asdu.New(asdu.CauseReturnRemote, station,
			asdu.SinglePoint{IOA: ioaSwitch, Value: cmd.Value, Time: asdu.Now()}))
	}
	mux.HandleFunc(asdu.C_SC_NA_1, command)
	mux.HandleFunc(asdu.C_SC_TA_1, command)

	var err error
	srv, err = server.New(mux,
		server.WithCommonAddrs(station),
		server.WithLogger(logger),
		server.WithStateHandler(func(s *server.Session, state iec104.State, _ error) {
			if state == iec104.StateStarted {
				// Tell a freshly started connection that the station is up.
				_ = s.Send(s.Context(), asdu.New(asdu.CauseInitialized, station,
					asdu.EndOfInitialization{Cause: asdu.InitLocalPowerOn}))
			}
		}))
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// The process: a frequency that wanders, reported once per second.
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				f := float32(50 + 0.05*math.Sin(float64(now.Unix())/10))
				proc.mu.Lock()
				proc.freq = f
				proc.mu.Unlock()
				_, _ = srv.Broadcast(ctx, asdu.New(asdu.CauseSpontaneous, station,
					asdu.MeasuredFloat{IOA: ioaFreq, Value: f, Time: asdu.At(now)}))
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("IEC 60870-5-104 station %d listening on %s", station, *addr)
	if err := srv.ListenAndServe(*addr); err != nil && err != server.ErrServerClosed {
		log.Fatal(err)
	}
}
