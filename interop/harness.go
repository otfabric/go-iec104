//go:build interop

// SPDX-License-Identifier: MIT

package interop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// adapter is one reference implementation, as a container image that follows
// the iec104-interop container contract.
type adapter struct {
	name  string
	image string
}

// The reference images this version of go-iec104 is qualified against:
// otfabric/iec104-interop v0.1.0 (lib60870-C v2.4.1, OpenMUC j60870 1.7.2),
// pinned by digest so that a run is reproducible. Moving to another release
// of iec104-interop means changing these two constants, and the Makefile and
// the interop workflow follow.
const (
	interopRelease       = "v0.1.0"
	defaultLib60870Image = "ghcr.io/otfabric/iec104-interop-lib60870@sha256:a1fbb44a16da39d5aa3f387456d1f2931811556e5a4298797a6b4ea64c4ef248"
	defaultOpenMUCImage  = "ghcr.io/otfabric/iec104-interop-openmuc@sha256:e1d15745d5e2005692f2844fb91c477826930b23fb772de14beb07da1942aa1a"
)

// adapters returns the reference implementations to test against. The image
// of each can be overridden, for example to try a local build or a candidate:
//
//	IEC104_INTEROP_LIB60870_IMAGE, IEC104_INTEROP_OPENMUC_IMAGE
//
// IEC104_INTEROP_ADAPTERS restricts the run to a comma-separated subset.
func adapters(t testing.TB) []adapter {
	t.Helper()
	all := []adapter{
		{"lib60870", getenv("IEC104_INTEROP_LIB60870_IMAGE", defaultLib60870Image)},
		{"openmuc", getenv("IEC104_INTEROP_OPENMUC_IMAGE", defaultOpenMUCImage)},
	}
	only := os.Getenv("IEC104_INTEROP_ADAPTERS")
	if only == "" {
		return all
	}
	var out []adapter
	for _, a := range all {
		for _, want := range strings.Split(only, ",") {
			if strings.TrimSpace(want) == a.name {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("IEC104_INTEROP_ADAPTERS=%q selects no adapter", only)
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var containerSeq atomic.Int64

func docker(args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// refServer is a running reference server container.
type refServer struct {
	adapter adapter
	name    string
	addr    string // host:port on loopback
}

// startServer runs the reference server of a with the baseline fixture and
// waits until it is ready. extra is appended to the "server" command (APCI
// parameters, for example).
func startServer(t testing.TB, a adapter, extra ...string) *refServer {
	t.Helper()
	// A fixed host port keeps the address stable across "docker restart".
	port := freePort(t)
	name := fmt.Sprintf("go-iec104-interop-%s-%d-%d", a.name, os.Getpid(), containerSeq.Add(1))
	args := append([]string{"run", "-d", "--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:2404", port), a.image, "server"}, extra...)
	if _, stderr, err := docker(args...); err != nil {
		t.Fatalf("start %s server: %v\n%s", a.name, err, stderr)
	}
	s := &refServer{adapter: a, name: name, addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	t.Cleanup(func() {
		if t.Failed() {
			out, errOut, _ := docker("logs", "--tail", "60", name)
			t.Logf("%s server log:\n%s%s", a.name, out, errOut)
		}
		_, _, _ = docker("rm", "-f", name)
	})
	s.waitReady(t)
	return s
}

// waitReady waits for the readiness file, which the server writes once the
// fixture is loaded and the listener is up.
func (s *refServer) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, _, err := docker("exec", s.name, "test", "-f", "/run/iec104-interop/ready"); err == nil {
			return
		}
		if state, _, _ := docker("inspect", "--format", "{{.State.Status}}", s.name); strings.TrimSpace(state) != "running" {
			t.Fatalf("%s server is %q, not running", s.adapter.name, strings.TrimSpace(state))
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server not ready after 60s", s.adapter.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// restart stops and starts the container, which drops every connection and
// resets the station to the fixture.
func (s *refServer) restart(t testing.TB) {
	t.Helper()
	if _, stderr, err := docker("restart", "-t", "5", s.name); err != nil {
		t.Fatalf("restart %s server: %v\n%s", s.adapter.name, err, stderr)
	}
	s.waitReady(t)
}

// event is one line of the server's JSON Lines event stream.
type event map[string]any

func (s *refServer) events(t testing.TB) []event {
	t.Helper()
	out, _, err := docker("logs", s.name)
	if err != nil {
		t.Fatalf("logs of %s server: %v", s.adapter.name, err)
	}
	var evs []event
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%s server wrote a stdout line that is not JSON: %q", s.adapter.name, line)
		}
		evs = append(evs, e)
	}
	return evs
}

// waitEvent returns the last event that satisfies match, waiting for one.
func (s *refServer) waitEvent(t testing.TB, what string, match func(event) bool) event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := s.events(t)
		for i := len(evs) - 1; i >= 0; i-- {
			if match(evs[i]) {
				return evs[i]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server reported no %s event; events: %v", s.adapter.name, what, evs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// result is the document a reference client prints: see the container
// contract of iec104-interop.
type result struct {
	OK         bool   `json:"ok"`
	Operation  string `json:"operation"`
	Connected  bool   `json:"connected"`
	StartDT    bool   `json:"startdtConfirmed"`
	StopDT     bool   `json:"stopdtConfirmed"`
	Terminated bool   `json:"terminated"`
	Error      *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Confirmations []struct {
		Cot      int  `json:"cot"`
		Negative bool `json:"negative"`
	} `json:"confirmations"`
	ASDUs []resultASDU `json:"asdus"`

	exit int
	raw  map[string]any
}

type resultASDU struct {
	Type       string         `json:"type"`
	TypeID     int            `json:"typeId"`
	Cot        int            `json:"cot"`
	Negative   bool           `json:"negative"`
	Test       bool           `json:"test"`
	Originator int            `json:"originator"`
	CommonAddr int            `json:"commonAddress"`
	Sequence   bool           `json:"sequence"`
	Objects    []resultObject `json:"objects"`
}

type resultObject map[string]any

// summary states the outcome in one line: what the scenario tables expect.
func (r *result) summary() string {
	code := "-"
	if r.Error != nil {
		code = r.Error.Code
	}
	var conf, asdus []string
	for _, c := range r.Confirmations {
		s := strconv.Itoa(c.Cot)
		if c.Negative {
			s += "n"
		}
		conf = append(conf, s)
	}
	for _, a := range r.ASDUs {
		asdus = append(asdus, fmt.Sprintf("%s/%d", a.Type, a.Cot))
	}
	return fmt.Sprintf("exit=%d ok=%v error=%s conf=%s term=%v asdus=%s",
		r.exit, r.OK, code, strings.Join(conf, ","), r.Terminated, strings.Join(asdus, ","))
}

// normalized returns the document without what legitimately differs between
// two runs: who answered, how long it took and wall-clock time tags.
func (r *result) normalized() string {
	doc := map[string]any{}
	for k, v := range r.raw {
		if k != "adapter" && k != "elapsedMs" {
			doc[k] = v
		}
	}
	if asdus, ok := doc["asdus"].([]any); ok {
		for _, a := range asdus {
			objs, _ := a.(map[string]any)["objects"].([]any)
			for _, o := range objs {
				delete(o.(map[string]any), "time")
			}
		}
	}
	b, _ := json.MarshalIndent(doc, "", " ")
	return string(b)
}

// runClient runs one operation of the reference client of a against a
// go-iec104 server listening on the host at addr, and returns its result
// document.
func runClient(t testing.TB, a adapter, addr string, args ...string) *result {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	// The client runs in a container and reaches the host through the
	// gateway alias, on Docker Desktop and on Linux alike. The server must
	// listen on all interfaces for that: on Linux the alias is the bridge
	// address, not loopback.
	return execClient(t, a, []string{"--add-host=host.docker.internal:host-gateway"},
		append(args, "--host", "host.docker.internal", "--port", port))
}

// runClientAgainst runs one operation of the reference client of a against
// a reference server. The client joins the network namespace of the server
// container: the server's port is published on the host's loopback only,
// which a container cannot reach on Linux.
func runClientAgainst(t testing.TB, a adapter, srv *refServer, args ...string) *result {
	t.Helper()
	return execClient(t, a, []string{"--network", "container:" + srv.name},
		append(args, "--host", "127.0.0.1", "--port", "2404"))
}

func execClient(t testing.TB, a adapter, dockerArgs, clientArgs []string) *result {
	t.Helper()
	cmd := append([]string{"run", "--rm"}, dockerArgs...)
	cmd = append(append(cmd, a.image, "client"), clientArgs...)
	stdout, stderr, err := docker(cmd...)
	r := &result{}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		r.exit = exitErr.ExitCode()
	default:
		t.Fatalf("run %s client: %v", a.name, err)
	}
	line := strings.TrimSpace(stdout)
	if strings.Count(line, "\n") != 0 || line == "" {
		t.Fatalf("%s client %v: want one result line on stdout, got %q (exit %d, stderr %q)",
			a.name, clientArgs, stdout, r.exit, stderr)
	}
	if err := json.Unmarshal([]byte(line), r); err != nil {
		t.Fatalf("%s client result is not JSON: %v\n%s", a.name, err, line)
	}
	if err := json.Unmarshal([]byte(line), &r.raw); err != nil {
		t.Fatal(err)
	}
	return r
}

func freePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// eventually polls cond until it holds or the timeout passes.
func eventually(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// logReference records which reference build a test ran against.
func logReference(t testing.TB, a adapter) {
	t.Helper()
	out, stderr, err := docker("run", "--rm", a.image, "print-capabilities")
	if err != nil {
		t.Fatalf("print-capabilities of %s: %v\n%s", a.image, err, stderr)
	}
	var caps struct {
		AdapterVersion string `json:"adapterVersion"`
		Upstream       struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"upstream"`
		Roles struct {
			Server bool `json:"server"`
			Client bool `json:"client"`
		} `json:"roles"`
	}
	if err := json.Unmarshal([]byte(out), &caps); err != nil {
		t.Fatalf("capabilities of %s are not JSON: %v", a.image, err)
	}
	if !caps.Roles.Server || !caps.Roles.Client {
		t.Fatalf("%s does not provide both roles", a.image)
	}
	t.Logf("%s: iec104-interop %s, %s %s (%s)", a.name, caps.AdapterVersion, caps.Upstream.Name, caps.Upstream.Version, a.image)
	if a.image == defaultLib60870Image || a.image == defaultOpenMUCImage {
		if caps.AdapterVersion != interopRelease {
			t.Errorf("%s is pinned as iec104-interop %s but reports %s", a.name, interopRelease, caps.AdapterVersion)
		}
	}
}

// TestReferences checks that the pinned images are what the documentation
// says this version is qualified against.
func TestReferences(t *testing.T) {
	for _, a := range adapters(t) {
		logReference(t, a)
	}
}
