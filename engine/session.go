package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Session states, as strings so gomobile can hand them straight to Kotlin and
// the UI can switch on them without a mapping table.
const (
	StateIdle       = "idle"
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateStopping   = "stopping"
	StateError      = "error"
)

// Snapshot is everything the UI needs to render one frame of the session. It is
// deliberately plain data: the Kotlin side copies it into Compose state and
// never holds a reference into Go.
//
// It reaches Kotlin as JSON (Engine.StatusJSON) rather than as a bound object,
// because gobind silently skips any method that takes or returns a struct by
// value - see the note on Engine.Connect.
type Snapshot struct {
	State    string `json:"state"`
	Proto    string `json:"proto"`
	Endpoint string `json:"endpoint"`
	ExitIP   string `json:"exitIP"`
	Country  string `json:"country"`
	Message  string `json:"message"`
	SinceMS  int64  `json:"sinceMS"`
	UptimeMS int64  `json:"uptimeMS"`

	// Data-plane facts the home screen shows next to the exit. They come from
	// the tun device itself, not from a proxy's statistics API (the desktop
	// client read them from mihomo's /traffic - there is no mihomo here).
	LatencyMS int64 `json:"latencyMS"`
	UpBps     int64 `json:"upBps"`
	DownBps   int64 `json:"downBps"`
	UpBytes   int64 `json:"upBytes"`
	DownBytes int64 `json:"downBytes"`

	// VPN is true only while the Android system VPN is really established. The
	// app must never say "connected" without it: a tunnel that nothing routes
	// into is indistinguishable from a broken one, which is exactly how this
	// looked before the VpnService path existed.
	VPN bool `json:"vpn"`

	// Egress 是最终出口的种类："" = 就是基础协议自己，psiphon / openvpn = 叠了
	// 第二跳。首页据此把协议标签显示成 "AWG·Psiphon" / "AWG·OpenVPN"。
	Egress string `json:"egress"`

	// NeedRecover 表示「这个会话已经判定为死掉，等上层断开重连」。
	//
	// 引擎自己不做重连：tun 是 Kotlin 那边的 VpnService 建的，重连必须由它
	// 重新 establish。这里只把判断结果写进快照，由 WarpVpnService 的看门狗执行
	// 「断开 → 换端点 → 重连」。界面看到它就该提示正在重连。
	NeedRecover bool `json:"needRecover"`
}

// session is the one piece of state the engine owns. It replaces the Windows
// client's "state.json + cross-process pid lease" model: on Android there is a
// single process, so a mutex is the whole concurrency story (see
// docs/porting-analysis.md, section 5).
type session struct {
	mu      sync.Mutex
	snap    Snapshot
	log     []string
	logSink LogSink
}

// logRingMax 要足够大，才能让「导出日志」拿到完整的一次会话而不是最后几行。
// Kotlin 侧另有一份同样的环形缓冲（EngineBridge），两边都调大才算真的完整。
const logRingMax = 2000

func newSession() *session {
	return &session{snap: Snapshot{State: StateIdle, Message: "未连接"}}
}

func (s *session) snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snap
	if out.SinceMS > 0 && out.State == StateConnected {
		out.UptimeMS = time.Since(time.UnixMilli(out.SinceMS)).Milliseconds()
	}
	return out
}

// transition moves the session and refuses the moves that would hide a bug:
// a stale goroutine from an abandoned connect must not be able to push the UI
// back into "connected" after the user already disconnected.
func (s *session) transition(to string, apply func(*Snapshot)) error {
	s.mu.Lock()
	from := s.snap.State
	if !canTransition(from, to) {
		s.mu.Unlock()
		return fmt.Errorf("session: 状态 %s 不能转到 %s", from, to)
	}
	s.snap.State = to
	if apply != nil {
		apply(&s.snap)
	}
	s.mu.Unlock()
	s.logf("[session] %s -> %s", from, to)
	return nil
}

// canTransition is the state machine. stopping may be entered from connecting
// because a user can cancel a connect, which is exactly what the Windows GUI
// could not do until the button click was wired to a per-connect context.
func canTransition(from, to string) bool {
	switch from {
	case StateIdle:
		return to == StateConnecting
	case StateConnecting:
		return to == StateConnected || to == StateStopping || to == StateError
	case StateConnected:
		return to == StateStopping || to == StateError
	case StateStopping:
		return to == StateIdle || to == StateError
	case StateError:
		return to == StateConnecting || to == StateIdle
	}
	return false
}

func (s *session) setExit(proto, endpoint, exitIP, country string) {
	s.mu.Lock()
	s.snap.Proto, s.snap.Endpoint, s.snap.ExitIP, s.snap.Country = proto, endpoint, exitIP, country
	s.snap.SinceMS = time.Now().UnixMilli()
	s.snap.Message = "已连接"
	s.mu.Unlock()
}

// setEgress records which second hop terminates the session ("" = none).
func (s *session) setEgress(kind string) {
	s.mu.Lock()
	s.snap.Egress = kind
	s.mu.Unlock()
}

func (s *session) setMessage(msg string) {
	s.mu.Lock()
	s.snap.Message = msg
	s.mu.Unlock()
}

// setStats records the sampler's latest numbers. Called every couple of seconds
// while connected, so it must stay cheap and never block the UI.
func (s *session) setStats(latencyMS, upBps, downBps, upBytes, downBytes int64) {
	s.mu.Lock()
	if latencyMS > 0 {
		s.snap.LatencyMS = latencyMS
	}
	s.snap.UpBps, s.snap.DownBps = upBps, downBps
	s.snap.UpBytes, s.snap.DownBytes = upBytes, downBytes
	s.mu.Unlock()
}

// setVPN records whether the system VPN is up. Kept separate from the session
// state machine on purpose: the state machine tracks the tunnel, this tracks
// the phone, and the UI needs both to tell "connected" from "connected and
// actually carrying this phone's traffic".
func (s *session) setVPN(up bool) {
	s.mu.Lock()
	s.snap.VPN = up
	s.mu.Unlock()
}

// markNeedsRecover 标记「会话已死，等上层重连」。
func (s *session) markNeedsRecover() {
	s.mu.Lock()
	s.snap.NeedRecover = true
	s.mu.Unlock()
}

// clearNeedsRecover 撤掉上面的标记（隧道自己恢复了，或者新一次连接开始了）。
func (s *session) clearNeedsRecover() {
	s.mu.Lock()
	s.snap.NeedRecover = false
	s.mu.Unlock()
}

// setSink installs the log callback the Kotlin service uses to push lines into
// the notification or a log screen. Written from the UI thread while the engine
// goroutine may be logging, hence the mutex.
func (s *session) setSink(sink LogSink) {
	s.mu.Lock()
	s.logSink = sink
	s.mu.Unlock()
}

// logf records one line and forwards it. It never blocks the caller on the
// sink: a slow Kotlin callback must not stall tunnel setup.
func (s *session) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	s.mu.Lock()
	s.log = append(s.log, line)
	if n := len(s.log); n > logRingMax {
		s.log = s.log[n-logRingMax:]
	}
	sink := s.logSink
	s.mu.Unlock()
	if sink != nil {
		sink.OnLog(line)
	}
}

func (s *session) logs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.log, "\n")
}
