package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBackend stands in for the warpscout port. block makes Connect hang until
// Close is called, which is how a cancel is expressed at this seam.
type fakeBackend struct {
	closed chan struct{}
	once   sync.Once
	res    Result
	err    error
	block  bool
}

func newFake(block bool) *fakeBackend { return &fakeBackend{closed: make(chan struct{}), block: block} }

func (f *fakeBackend) Connect(ctx context.Context, _ Request, _ func(string)) (Result, error) {
	if f.block {
		select {
		case <-f.closed:
		case <-ctx.Done():
		}
		return Result{}, errors.New("connect cancelled")
	}
	return f.res, f.err
}

func (f *fakeBackend) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func waitState(t *testing.T, e *Engine, want string, d time.Duration) Snapshot {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s := e.status()
		if s.State == want {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	return e.status()
}

// NewEngine 现在会装上真正的 WARP 后端，所以这条错误路径要显式换成占位实现，
// 否则测试会真的去连 Cloudflare。
func TestConnectWithoutBackendFailsLoudly(t *testing.T) {
	e := NewEngine(t.TempDir())
	e.setBackend(unwiredBackend{})
	if err := e.Connect("wg", "", false, false, 1280); err != nil {
		t.Fatalf("Connect should start, not fail synchronously: %v", err)
	}
	s := waitState(t, e, StateError, 2*time.Second)
	if !strings.Contains(s.Message, "尚未接入") {
		t.Fatalf("expected the unwired error, got %q", s.Message)
	}
}

func TestConnectThenDisconnect(t *testing.T) {
	e := NewEngine(t.TempDir())
	fake := newFake(false)
	fake.res = Result{ExitIP: "165.22.50.89", Country: "AU", Endpoint: "8.35.211.17:943"}
	e.setBackend(fake)

	if err := e.Connect("wg", "8.35.211.17:943", false, false, 1280); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	s := waitState(t, e, StateConnected, 2*time.Second)
	if s.ExitIP != "165.22.50.89" || s.Country != "AU" {
		t.Fatalf("exit not recorded: %#v", s)
	}
	if s.UptimeMS < 0 {
		t.Fatalf("uptime negative: %#v", s)
	}
	if err := e.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if s := e.status(); s.State != StateIdle || s.ExitIP != "" {
		t.Fatalf("not reset after disconnect: %#v", s)
	}
}

// The Kotlin side reads these keys, and gobind's struct-by-value limitation is
// what forced the JSON shape on us - so pin it.
func TestStatusJSONShape(t *testing.T) {
	e := NewEngine(t.TempDir())
	raw := e.StatusJSON()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("StatusJSON is not valid JSON (%v): %s", err, raw)
	}
	for _, key := range []string{"state", "proto", "endpoint", "exitIP", "country", "message", "sinceMS", "uptimeMS"} {
		if _, ok := got[key]; !ok {
			t.Errorf("StatusJSON missing key %q: %s", key, raw)
		}
	}
	if got["state"] != StateIdle {
		t.Errorf("state: got %v want %v", got["state"], StateIdle)
	}
}

// The desktop GUI's worst bug was a click during "connecting" that was simply
// swallowed. On Android the same click cancels, so it gets a test.
func TestDisconnectDuringConnectingCancels(t *testing.T) {
	e := NewEngine(t.TempDir())
	fake := newFake(true)
	e.setBackend(fake)

	if err := e.Connect("awg", "", false, false, 1280); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if s := waitState(t, e, StateConnecting, time.Second); s.State != StateConnecting {
		t.Fatalf("expected connecting, got %s", s.State)
	}
	if err := e.Disconnect(); err != nil {
		t.Fatalf("Disconnect while connecting: %v", err)
	}
	s := waitState(t, e, StateIdle, 2*time.Second)
	if s.State != StateIdle {
		t.Fatalf("cancel did not settle to idle: %#v", s)
	}
	if s.Message != "未连接" {
		t.Fatalf("cancel left a stale message: %q", s.Message)
	}
}

func TestStaleConnectCannotReviveAfterStop(t *testing.T) {
	if canTransition(StateStopping, StateConnected) {
		t.Fatal("stopping -> connected must be refused")
	}
	if canTransition(StateIdle, StateConnected) {
		t.Fatal("idle -> connected must be refused")
	}
	if !canTransition(StateConnecting, StateStopping) {
		t.Fatal("connecting -> stopping (cancel) must be allowed")
	}
}

func TestRenderUAPI(t *testing.T) {
	device, err := RenderDeviceUAPI("AQID", true, AWGJunk{Jc: 4, Jmin: 20, Jmax: 60, I1: "deadbeef"})
	if err != nil {
		t.Fatalf("device uapi: %v", err)
	}
	for _, want := range []string{"private_key=010203\n", "jc=4\n", "jmin=20\n", "jmax=60\n", "i1=deadbeef\n"} {
		if !strings.Contains(device, want) {
			t.Errorf("device uapi missing %q:\n%s", want, device)
		}
	}

	// A plain wg tunnel must not carry the AmneziaWG keys.
	plain, err := RenderDeviceUAPI("AQID", false, AWGJunk{})
	if err != nil {
		t.Fatalf("plain uapi: %v", err)
	}
	if strings.Contains(plain, "jc=") {
		t.Errorf("plain wg must not emit junk parameters:\n%s", plain)
	}

	peer, err := RenderPeerUAPI("AQID", "8.35.211.17:943", 0)
	if err != nil {
		t.Fatalf("peer uapi: %v", err)
	}
	for _, want := range []string{"replace_peers=true\n", "public_key=010203\n", "endpoint=8.35.211.17:943\n",
		"allowed_ip=0.0.0.0/0\n", "allowed_ip=::/0\n", "persistent_keepalive_interval=25\n"} {
		if !strings.Contains(peer, want) {
			t.Errorf("peer uapi missing %q:\n%s", want, peer)
		}
	}

	if _, err := RenderPeerUAPI("AQID", "", 25); err == nil {
		t.Error("an empty endpoint must be refused")
	}
	if _, err := RenderDeviceUAPI("not base64!", false, AWGJunk{}); err == nil {
		t.Error("a malformed key must be refused")
	}
}
