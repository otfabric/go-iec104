// SPDX-License-Identifier: MIT

// Package server implements the controlled station (outstation, slave) of
// IEC 60870-5-104.
//
// A [Server] accepts connections and runs the protocol machine of each one
// in a [Session]. ASDUs received in control direction are passed to a
// [Handler]; [Mux] routes them by type identification and rejects what the
// application does not serve, as the standard requires.
//
//	mux := server.NewMux()
//	mux.HandleFunc(asdu.C_IC_NA_1, func(s *server.Session, req *asdu.ASDU) {
//		_ = s.Confirm(req)
//		_ = s.Send(s.Context(), asdu.New(asdu.CauseInterrogatedStation, req.CommonAddr,
//			asdu.MeasuredFloat{IOA: 4001, Value: 49.98}))
//		_ = s.Terminate(req)
//	})
//	srv, err := server.New(mux, server.WithCommonAddrs(1))
//	if err != nil { ... }
//	log.Fatal(srv.ListenAndServe(":2404"))
//
// A [FileServer] registered for [FileTypes] serves files to controlling
// stations.
//
// Events are queued with [Server.Enqueue]: each redundancy group delivers
// them in order to its one started connection and keeps them until the
// controlling station has acknowledged them. [Session.Send] and
// [Server.Broadcast] send immediately and buffer nothing. All methods are
// safe for concurrent use.
package server
