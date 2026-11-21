//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/lxn/walk"

	"github.com/xhwarp/warp-client/internal/core"
)

// guiNativeAvailable reports that this platform builds a native window.
const guiNativeAvailable = true

// fonts is the whole type ramp plus a monospace face for the log console. The
// palettes live in gui_theme_windows.go.
//
// The numbers in the token names are the ramp's *steps*, not point sizes: the
// real size of every face is fontSpecs' pt value times the window scale, so a
// maximised window enlarges type with the cards instead of leaving 9pt text
// swimming in a 1.5x layout. Steps are spaced by role (caption 9 / label 10 /
// body 11 / value 17 / title 15), which is what keeps the cards looking
// related instead of hand-sized.
type fonts struct {
	f8, f9, f10, f10b, f11b, f12b, f12, f13, f13b, f15, f15b, f16b, f17b, f18b, f22b, f25b, f30b *walk.Font
	fmono, fmonoL                                                                                *walk.Font
}

// fontSpec is one face of the ramp: where to store it, its family and its size
// at window scale 1.0 (the 1080x700 design grid).
type fontSpec struct {
	dst   **walk.Font
	name  string
	pt    int
	style walk.FontStyle
}

// uiFont is the typeface: the Windows UI variant of YaHei is the closest thing
// to the macOS system look that ships with every Chinese Windows install — it
// is lighter and better hinted than plain "Microsoft YaHei".
const uiFont = "Microsoft YaHei UI"
const uiFontFallback = "Microsoft YaHei"

// ---------------------------------------------------------------------------
// Model — mutated only on the GUI thread; workers compute off-thread and hand
// results back through mw.Synchronize.
// ---------------------------------------------------------------------------

type natModel struct {
	proto      string
	outerProto string // WARP-in-WARP outer carrier (wg|awg)
	innerProto string // WARP-in-WARP inner tunnel (wg|awg)
	psiphon    bool   // Psiphon exit switch: base protocol + Psiphon (never for chained protocols)
	openvpn    bool   // OpenVPN (VPN Gate) exit switch; mutually exclusive with Psiphon
	// vpnCountries is the VPN Gate pool grouped by country, for the OpenVPN
	// region dropdown. It is derived from the cached node list, so the popup
	// never offers a country with no node behind it. vpnNodes keeps the full
	// pool so an expanded country can list its relays with measured latency.
	vpnNodes     []vpnGateNode
	vpnCountries []vpnGateCountry
	vpnExpanded  string // country whose node list is open in the popup
	vpnPoolBusy  bool
	vpnPoolNote  string
	vpnScroll    int  // vpnregion popup scroll (rows)
	regionScroll int  // Psiphon region popup scroll (rows)
	vpnProbeBusy bool // latency probe for the cached pool is in flight
	vpnMeasured  bool // the current pool already carries measured latency
	// Progress for the manual test, drawn under the picker header.
	vpnProbeDone  int
	vpnProbeTotal int
	// vpnProbeOK / vpnProbeFail split the finished run so the result line says
	// how many relays actually answered instead of only "12/12 completed",
	// which read as success when every row had failed.
	vpnProbeOK   int
	vpnProbeFail int
	// probeResults keeps this session's measured state per node ID. The pool
	// slice is rebuilt on every refresh (which resets every row to 未检测), so
	// results stored only on the nodes vanished from the list while the header
	// still said "测试完成". Keyed by id, they survive a rebuild.
	probeResults    map[string]probeResult
	vpnProbeCurrent string
	vpnProbeNote    string // scope: 全部 / 指定国家 / 指定节点

	endpoints []cachedEndpoint
	pin       string
	scanFresh bool
	scanAt    time.Time
	// subTestAt is when the last subscription latency test finished; the mode
	// page footer shows it as 上次测试 in subscription mode.
	subTestAt time.Time

	connecting bool
	// cancelling is true between the cancel click and the pipeline returning:
	// the button says "正在取消…" instead of pretending to still connect.
	cancelling bool
	// connectAt is when the current attempt started: the button shows the
	// elapsed seconds, which is what tells a user "it is still working" even
	// between animation frames.
	connectAt time.Time
	working   bool // true while a connect/disconnect goroutine is in flight
	connected bool
	status    clientState
	latency   int64 // live delay ms: through the tunnel, or direct when idle
	samples   []int64
	upRates   []int64 // live throughput samples, bytes/sec (upload)
	downRates []int64 // live throughput samples, bytes/sec (download)
	// Session byte totals and per-direction peaks for the home traffic card.
	// Totals come from the core's /connections counters (cumulative for the
	// run); peaks are the largest rate sample seen this session. Both clear
	// with the rate rings on disconnect.
	sessionUp   int64
	sessionDown int64
	peakUp      int64
	peakDown    int64
	// shareBytes is the live per-category byte split from /connections, indexed
	// by the shareCat* constants; shareTotal is their sum. A zero total hides
	// the share panel rather than drawing a fabricated split.
	shareBytes [5]int64
	shareTotal int64
	// homeNodeScroll is the home node dropdown's list offset, in rows.
	homeNodeScroll int

	// The machine's own coordinates, shown on the home tiles while no tunnel
	// is up: the LAN address, and the public IP's country/city.
	localLan  string
	localIP   string
	localCC   string
	localCity string

	logs []natLog // newest last; capped by addLog

	coreInstalled bool
	coreSize      int64
	coreBusy      bool
	coreVersion   string          // parsed from `mihomo -v` by the capability probe
	capab         map[string]bool // protocol → core can parse its config

	proxyBlocker   string // security suite detected while ProxyWarn is set (banner hint)
	blockerChecked bool   // DetectProxyBlocker ran once (touched only by statusLoop)

	// proxyLost means the session is up but the host proxy no longer points at
	// our port (another client rewrote WinINET). Every browser then goes out
	// directly, so the home page must stop saying 已连接.
	proxyLost bool

	hover  string
	spin   int
	scroll int // node list scroll (rows)
	// Settings scroll: design-pixel offset into the single settings column and
	// the furthest it may go, both recomputed by the page each paint.
	setScroll    int
	setScrollMax int
	// dropOpen names the currently open dropdown popup ("", "region" or
	// "proto"). One at a time; a click anywhere else closes it.
	dropOpen string

	// Shell state: which page, which tab inside it, and the node list's own
	// view (search text, filter, sort, how many rows fit).
	page            string
	nodeSearch      string
	nodeFilter      string
	nodeSort        string
	nodeVisibleRows int
	// Subscription grid: rows that fit, and the largest scroll offset. The
	// wheel uses these instead of the WARP endpoint count in mode B.
	subVisibleRows int
	subMaxScroll   int
	// subTesting marks nodes whose latency test is in flight, so the list can
	// animate 未检测 → 测试中(spinner) → 延迟. Nil when no test is running.
	subTesting map[string]bool
	// subMgrScroll is the subscription-manager popup's list offset, in rows.
	subMgrScroll   int
	logTab         string
	logScroll      int // run-log lines scrolled up from the newest; 0 follows live
	logVisibleRows int // rows the last run-log paint could show

	// set is the persisted preference file, kept in the model so every page
	// renders straight from it.
	set       clientSettings
	setDirty  bool // a setting changed while connected: reconnect applies it
	updLatest string
	// updAvail is the version a completed check found to be newer; when it is
	// set the update card's primary button installs it instead of checking.
	updAvail   string
	updChecked bool
	updTime    time.Time
	updBusy    bool
	updNote    string

	// Remote control: this install's code lives in the settings file, and
	// control is the last verdict read from the published stop list. The
	// verdict is cached on disk, so a restart cannot quietly put a stopped
	// client back into service while the network is unreachable.
	control     controlState
	controlBusy bool

	// geoBusy is true while the geo databases the bypass preset needs are
	// downloading, so a second click cannot start a second transfer.
	geoBusy bool

	// scrollDrag is the settings scrollbar's grab state. The wheel alone was
	// the only way to scroll that page, which is what users complained about.
	scrollDrag   bool
	scrollGrabDY float64 // pointer offset inside the thumb, design units

	// connectCancel stops the connect pipeline started by connectAsync. The
	// button stays clickable while connecting, and that click has to do
	// something rather than being swallowed.
	connectCancel context.CancelFunc
}

// natLog is one line of the log panel.
type natLog struct {
	at    time.Time
	text  string
	lv    int  // 0 = info, 1 = warning, 2 = error
	core  bool // came from the mihomo core, not the client itself
	stage bool // connection pipeline progress: the "sessions" view's material
}

func newNatModel() *natModel {
	return &natModel{
		proto:      protoWG,
		outerProto: protoWG,
		innerProto: protoWG,
		samples:    make([]int64, 0, 240),
		page:       pageHome,
		nodeFilter: "all",
		nodeSort:   "latency",
		logTab:     "run",
		set:        defaultSettings(),
	}
}

// ---------------------------------------------------------------------------
// UI + spot hit-testing
// ---------------------------------------------------------------------------

type spot struct {
	id      string
	r       walk.Rectangle
	enabled bool
}

type natUI struct {
	mw *walk.MainWindow
	cw *walk.CustomWidget

	m *natModel

	// lastHealAt paces the periodic stale-proxy sweep: the startup heal can be
	// skipped while an orphan core still holds the port, and the orphan dies
	// seconds later, so one check at launch is not enough.
	lastHealAt time.Time

	f  fonts
	sp []spot
	k  float64

	// The layout is adaptive: k is the display's DPI factor (times a shrink
	// factor on short non-home pages), ox/oy stay zero, and dw/dh are the
	// logical client width/height the breakpoints lay out against. dh excludes
	// the caption band. winW is the DPI-only logical width (no page shrink), so
	// the sidebar breakpoint does not drift when a short page is scaled down.
	ox, oy int
	dw, dh float64
	winW   float64
	// fonts is the ramp's construction table, and fontK the scale it was built
	// for: paint rebuilds the whole ramp when the window scale drifts.
	fonts []fontSpec
	fontK float64

	glowSpr map[string]*glowSprite

	ctx    context.Context
	cancel context.CancelFunc

	// repairing keeps only one repair inside this process. Ownership keeps
	// other processes out, but nothing stops this loop from meeting the fail
	// count again while the goroutine it already spawned is still verifying a
	// candidate - and two repairs at once means two sets of core kills,
	// state writes and proxy changes interleaved on one session.
	repairing atomic.Bool

	// controlChecking serialises the remote-control check: the periodic loop
	// and the About page's button can fire at the same moment, and two checks
	// racing on one cached verdict would let the slower (stale) answer win.
	controlChecking atomic.Bool

	// rescanBusy keeps a burst of clicks on the refresh button (or a click
	// landing while the frame is redrawn) from starting several 1-2 minute
	// scans at once. Each one re-registers, rewrites the endpoint cache and
	// logs "重新扫描 WARP 端点" — four identical lines in one second were
	// four concurrent scans, not one.
	rescanBusy atomic.Bool

	// subDelayBusy keeps only one subscription latency test in flight; each
	// one starts its own temporary mihomo core.
	subDelayBusy atomic.Bool
	// subRefreshBusy keeps only one subscription re-fetch in flight: the
	// refresh button re-downloads every remembered URL.
	subRefreshBusy atomic.Bool
	// probeCarrier is the WARP base the OpenVPN probe dials through, prepared
	// once per run and cleared when it ends. Written before the probe workers
	// start, read by them, never touched by the painter.
	probeCarrier *probeCarrier

	// ni is the tray icon. Closing the window hides it there instead of
	// quitting, so the tunnel keeps running; the close is only allowed once
	// u.quitting is set from the tray menu.
	ni            *walk.NotifyIcon
	quitting      bool
	quitScheduled bool
	trayHinted    bool
	trayAttempts  int
	trayFailed    bool

	// scrollDrag is the settings scrollbar's grab state: the wheel used to be
	// the only way to scroll that page, which is what users complained about.
	scrollDrag   bool
	scrollGrabDY float64 // pointer offset inside the thumb, design units

	// logDrag is the run-log scrollbar's grab state, same contract as the
	// settings one: the thumb must be draggable, not wheel-only.
	logDrag   bool
	logGrabDY float64

	// pageAnimAt stamps a page switch so paintShell can slide/fade the new page
	// in; spinLoop keeps repainting until the transition window closes.
	pageAnimAt time.Time
	// ax/ay are the transient page-transition offset, in device pixels, added
	// into sx/sy (and removed in ux/uy). Zero except mid-transition.
	ax, ay int

	// connectCancel stops the connect pipeline started by connectAsync. The
	// button stays clickable while connecting, and that click has to do
	// something rather than being swallowed.
	connectCancel context.CancelFunc

	// stateEpoch invalidates a status-loop tick that loaded state before a
	// connect/disconnect/repair finished. Without it, an idle tick that was
	// already probing the local network when a connect completed applied the
	// stale connected:false snapshot last, and the freshly connected home page
	// flipped back to the LAN IP and local flag until the next tick.
	stateEpoch atomic.Int64
}

// s scales a length (width, height, radius) from the design grid to pixels.
func (u *natUI) s(v float64) int { return int(v*u.k + 0.5) }

// sx / sy scale a coordinate and add the centring offset; only these two may be
// used for an x or a y. Lengths go through s. sy also skips the caption band, so
// every page can keep using 0 as its own top edge while the window draws its
// buttons above it.
func (u *natUI) sx(v float64) int { return u.ox + u.ax + u.s(v) }
func (u *natUI) sy(v float64) int { return u.oy + u.ay + u.s(v+capH) }

// ux / uy are the inverse, for the few places that reason about a point the
// canvas already drew (the sparkline column fill).
func (u *natUI) ux(px int) float64 { return (float64(px) - float64(u.ox+u.ax)) / u.k }
func (u *natUI) uy(px int) float64 { return (float64(px) - float64(u.oy+u.ay)) / u.k }

func (u *natUI) r(x, y, w, h float64) walk.Rectangle {
	return walk.Rectangle{X: u.sx(x), Y: u.sy(y), Width: u.s(w), Height: u.s(h)}
}

func (u *natUI) p(x, y float64) walk.Point { return walk.Point{X: u.sx(x), Y: u.sy(y)} }

// pxRect is a rectangle given entirely in device pixels: full-bleed surfaces
// (the window, the sidebar strip) are not part of the design grid.
func pxRect(x, y, w, h int) walk.Rectangle {
	return walk.Rectangle{X: x, Y: y, Width: w, Height: h}
}

func (u *natUI) addSpot(id string, r walk.Rectangle, enabled bool) {
	u.sp = append(u.sp, spot{id: id, r: r, enabled: enabled})
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func runNativeGUI(ctx context.Context, _ options) error {
	redirectLogs()
	logStartupDiagnostics()
	enableDPIAwareness()

	// Closing the window only hides it, so a second double-click would start a
	// second client that fights this one for the mixed port and adds a second
	// tray icon. One instance per desktop; a repeat launch just raises the
	// existing window.
	if !claimSingleInstance() {
		return nil
	}

	mw, err := walk.NewMainWindow()
	if err != nil {
		return fmt.Errorf("create window: %w", err)
	}
	if tb := mw.ToolBar(); tb != nil {
		tb.SetVisible(false)
	}
	// walk creates a status bar that nobody asked for. It is part of the client
	// area, and once the caption is stripped it turns into a grey strip under the
	// page that also pushes the window past the work area. The client is the
	// 1080x734 design grid and nothing else.
	if sb := mw.StatusBar(); sb != nil {
		sb.SetVisible(false)
	}
	mw.SetTitle("XEHN VPN Client")
	// Design units are 96-DPI logical pixels, so the initial client is scaled by
	// the display DPI: on a 200% screen the same window would otherwise open at
	// half its intended apparent size with tiny text. fitDesignWindow caps and
	// centres it once the window knows its monitor.
	dpi := windowDPI(uintptr(mw.Handle()))
	if err := mw.SetClientSizePixels(walk.Size{
		Width:  int(math.Round(defaultW * dpi / 96)),
		Height: int(math.Round(defaultH * dpi / 96)),
	}); err != nil {
		mw.Dispose()
		return fmt.Errorf("set client size: %w", err)
	}
	// The pages are adaptive, so the floor is the smallest layout they support
	// rather than a scaled copy of one fixed grid. WM_GETMINMAXINFO enforces the
	// same floor in physical pixels during a drag.
	mw.SetMinMaxSizePixels(walk.Size{
		Width:  int(math.Round(minW * dpi / 96)),
		Height: int(math.Round(minH * dpi / 96)),
	}, walk.Size{})

	u := &natUI{
		mw:  mw,
		m:   newNatModel(),
		sp:  make([]spot, 0, 128),
		ctx: ctx,
	}

	// Preferences first, so the window opens with the theme and language the
	// user chose last time. Autostart is read back from the registry rather
	// than trusted from the file: the registry is what actually launches the
	// program, and a value removed by hand must not keep showing as "on".
	// A leftover .new means an earlier update never finished; a leftover .old
	// means it did and this is the new binary. Either way, clear them.
	if exe, eerr := os.Executable(); eerr == nil {
		cleanupUpdateLeftovers(exe)
	}

	u.m.set = loadSettings()
	// A previous session that was killed from Task Manager (or crashed) never
	// got to put WinINET back, and the browser then stays pointed at a port
	// nobody listens on — the reported "no internet after quitting". Heal it
	// before anything else can rely on the proxy state.
	u.healStaleProxy()
	u.m.set.AutoStart = autoStartEnabled()
	u.syncSessionFromSettings()

	// Every install carries a control code from its first run: it is what the
	// published stop list matches against, so it has to exist before the first
	// check. Minting it here (not in the settings page) means a client that
	// never opens Settings still reports an identity.
	if u.m.set.ensureControlCode() {
		if err := saveSettings(u.m.set); err != nil {
			u.addLog(tr("设置保存失败: ")+err.Error(), true)
		}
	}
	// The cached verdict is applied before any network call: a client stopped
	// last run stays stopped even when this run starts offline.
	u.m.control = loadControlState()
	u.m.control.Code = u.m.set.ControlCode
	u.applyTheme()
	u.applyLang()

	// Hierarchy comes from size and colour; bold is reserved for values and
	// titles. Nav and body text stay regular so small windows never look chunky.
	u.fonts = []fontSpec{
		{&u.f.f8, uiFont, 9, 0},                // caption / hint
		{&u.f.f9, uiFont, 10, 0},               // label, list text
		{&u.f.f10, uiFont, 11, 0},              // body
		{&u.f.f10b, uiFont, 11, walk.FontBold}, // body, emphasised
		{&u.f.f11b, uiFont, 11, walk.FontBold}, // card title
		{&u.f.f12b, uiFont, 12, walk.FontBold}, // stat value, tab
		{&u.f.f12, uiFont, 10, 0},              // small
		{&u.f.f13, uiFont, 11, 0},              // sidebar status
		{&u.f.f13b, uiFont, 12, walk.FontBold}, // brand, button word
		{&u.f.f15, uiFont, 15, 0},              // nav labels, regular weight
		{&u.f.f15b, uiFont, 15, walk.FontBold}, // page title
		{&u.f.f16b, uiFont, 13, walk.FontBold}, // sidebar item
		{&u.f.f17b, uiFont, 15, walk.FontBold}, // big value (IP, rate, ms)
		{&u.f.f18b, uiFont, 17, walk.FontBold}, // display
		{&u.f.f22b, uiFont, 18, walk.FontBold}, // display, large
		{&u.f.f25b, uiFont, 20, walk.FontBold}, // hero
		{&u.f.f30b, uiFont, 24, walk.FontBold}, // hero, large
		{&u.f.fmono, "Consolas", 10, 0},
		{&u.f.fmonoL, "Consolas", 16, 0},
	}
	if err := u.rebuildFonts(1); err != nil {
		mw.Dispose()
		return err
	}

	cw, err := walk.NewCustomWidgetPixels(mw, 0, u.paint)
	if err != nil {
		mw.Dispose()
		return err
	}
	cw.SetPaintMode(walk.PaintBuffered)
	cw.SetBoundsPixels(mw.ClientBoundsPixels())
	u.cw = cw

	// The custom widget is the form's only child and must fill it. Without a
	// layout, FormBase.startLayout() (run when the window becomes visible)
	// dereferences a nil layout; a zero-margin VBox stretches the greedy
	// custom widget across the whole client area.
	layout := walk.NewVBoxLayout()
	_ = layout.SetMargins(walk.Margins{})
	_ = layout.SetSpacing(0)
	if err := mw.SetLayout(layout); err != nil {
		mw.Dispose()
		return fmt.Errorf("set layout: %w", err)
	}

	u.ctx, u.cancel = context.WithCancel(ctx)

	mw.SizeChanged().Attach(func() {
		b := mw.ClientBoundsPixels()
		cw.SetBoundsPixels(walk.Rectangle{X: 0, Y: 0, Width: b.Width, Height: b.Height})
		cw.Invalidate()
	})

	cw.MouseDown().Attach(func(x, y int, _ walk.MouseButton) { u.onDown(x, y) })
	cw.MouseMove().Attach(func(x, y int, b walk.MouseButton) { u.onMove(x, y, b) })
	cw.MouseWheel().Attach(func(x, y int, b walk.MouseButton) { u.onWheel(x, y, b) })

	go u.statusLoop()
	go u.shareLoop()
	go u.spinLoop()
	go u.guardLogLoop()
	go u.probeCore()         // stats the core, asks it which protocols it can parse
	u.reloadEndpoints(false) // fast cache read on the (main) GUI goroutine
	// Pool refresh and latency tests are MANUAL ONLY now. Startup only reads an
	// already cached list: no network fetch, no TCP probe, no classification.
	u.loadVPNGateCacheOnly()

	// Closing the window parks it in the tray instead of quitting: the session
	// keeps running, which is what a VPN client has to do. Only the tray menu's
	// "exit" sets u.quitting and lets the close through.
	mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if u.quitting {
			return
		}
		if u.ni == nil || u.trayFailed {
			// Without a tray icon there is no way back to a hidden window, so
			// closing has to mean closing.
			u.quitting = true
			return
		}
		*canceled = true
		mw.Hide()
		if !u.trayHinted {
			u.trayHinted = true
			u.trayHint()
		}
	})

	mw.Show()
	u.initTray()
	// The window owns its top edge: no OS caption, no title text, only the three
	// buttons the page paints. Done after Show, because creating/showing the form
	// applies walk's own window styles.
	u.stripCaptionBar()
	u.fitDesignWindow()
	u.constrainWindowToWorkArea()
	u.setWindowIcon()
	u.invalidate()

	// The licence reminder comes first: it is a condition of using this build,
	// and it must not be buried under an auto-connect pipeline or a scan.
	u.showStartupNotice()
	if u.m.control.Stopped {
		u.controlStoppedDialog()
	}
	// Check once now (the cached verdict may be hours old), then keep checking
	// for as long as the window lives.
	u.startControlCheck(false)
	go u.controlLoop()

	// Auto-connect starts here, after the window exists: the connect pipeline
	// posts its progress through Synchronize, which is a PostMessage and simply
	// waits in the queue until Run drains it below.
	if u.m.set.AutoConnect {
		u.addLog(tr("设置：启动后自动连接"), false)
		u.doConnect()
	}

	_ = mw.Run()

	// Stop the workers before tearing anything down, so no goroutine posts into
	// a disposed window.
	if u.cancel != nil {
		u.cancel()
	}
	// The session choices (protocol, TUN, Psiphon, autostart) are part of the
	// preference file too, so closing the window is the last chance to record
	// them for the next run.
	u.persistSession()
	// State on disk is the source of truth (the UI flag can lag a connect
	// that just finished), so always run the disconnect cleanup: the system
	// proxy must never outlive the window, and the elevated daemon (when in
	// use) makes the restore silent. Safe on an already-disconnected machine.
	// Bounded: a wedged core kill, or a proxy restore that falls back to the
	// elevated helper and waits on a UAC prompt, must not keep a windowless
	// process alive in Task Manager.
	done := make(chan struct{})
	go func() {
		_ = runDisconnectCmd(context.Background(), options{mixedPort: core.DefaultMixedPort})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	// Last line of defence, and it runs on both paths. runDisconnectCmd restores
	// the snapshot, but that call can wedge (elevation prompt nobody answered,
	// security software swallowing the write) and the state file can be missing
	// entirely. A host proxy pointing at a port whose core just died is the
	// single worst outcome of this program: the user closes it and every page
	// times out until they find Windows' proxy settings. Clearing is idempotent
	// and only touches the proxy when it names our port.
	clearProxyIfOurs(u.m.set.MixedPort, core.DefaultMixedPort)
	// Hand health ownership back: this window's claim must not outlive it, or
	// every other process would keep standing aside for an owner that left.
	releaseHealthOwner(os.Getpid())
	u.disposeFonts()
	u.freeGlowSprites()
	disposeLogo()
	cw.Dispose()
	mw.Dispose()
	return nil
}

// healStaleProxy clears a WinINET proxy that still points at our mixed port
// while nothing is listening on it. It is the startup half of the cleanup: the
// exit path restores the proxy, and this catches the sessions that never reached
// it (killed, crashed, or a restore that was blocked).
// healProxyIfStale clears a host proxy that points at our port while nothing is
// listening on it. Safe to call off the GUI thread; returns true when it
// actually cleared something, so the caller can log it once.
func healProxyIfStale(port int) bool {
	if port <= 0 {
		port = core.DefaultMixedPort
	}
	if !core.SystemProxyEnabledAt(port) {
		return false
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		return false
	}
	return core.ClearSystemProxy() == nil
}

func (u *natUI) healStaleProxy() {
	port := u.m.set.MixedPort
	if port <= 0 {
		port = core.DefaultMixedPort
	}
	if !core.SystemProxyEnabledAt(port) {
		return
	}
	// A core left behind by a killed session still holds the port, so the
	// liveness probe below would see a listener and keep a proxy that is about
	// to die with the orphan. Sweep the orphans first — that is exactly the
	// sequence behind "I closed it, reopened it, still no internet": the stale
	// core answered the probe, the heal was skipped, then the watchdog killed
	// the core and the proxy was left pointing at nothing.
	if cDir, err := coreDir(); err == nil {
		_ = core.KillStaleCores(core.CoreInDir(cDir))
	}
	// Only stale when nothing answers: a second instance or a live core would
	// own this port, and clearing then would break a working session.
	if !healProxyIfStale(port) {
		return
	}
	u.addLog(trf("已清理上次退出残留的系统代理（127.0.0.1:%d）", port), false)
}

func (u *natUI) disposeFonts() {
	for _, spec := range u.fonts {
		if f := *spec.dst; f != nil {
			f.Dispose()
			*spec.dst = nil
		}
	}
}

// rebuildFonts recreates the whole type ramp at the given zoom: every face is
// its design size times zoom, so at 1.5x the text is 1.5x too and the layout
// keeps the proportions it was designed with. Painted text is the only part of
// this window that is not scaled by the geometry helpers, and without this the
// cards grow while the words inside them stay 9pt.
//
// zoom is not u.k: k also contains the display's DPI (a 200% screen gives
// k = 2 for the default window), and GDI already renders a point size at that
// DPI. Dividing it out leaves the pure "the user made the window bigger"
// factor — the one thing the fonts have to follow.
//
// It is called from paint (the GUI thread) and only when the scale actually
// moved, so a drag-resize rebuilds at most a few dozen times.
func (u *natUI) rebuildFonts(zoom float64) error {
	if zoom <= 0 {
		zoom = 1
	}
	u.fontK = zoom
	for _, spec := range u.fonts {
		// The floor must stay low: at 200% DPI a 1:1 window needs zoom 0.5,
		// where a 6pt clamp would inflate every small face by a third.
		pt := int(math.Round(float64(spec.pt) * zoom))
		if pt < 3 {
			pt = 3
		}
		f, err := walk.NewFont(spec.name, pt, spec.style)
		if err != nil && spec.name != uiFontFallback {
			// The UI variant is missing on very old installs: fall back once.
			f, err = walk.NewFont(uiFontFallback, pt, spec.style)
		}
		if err != nil {
			return fmt.Errorf("font: %w", err)
		}
		if old := *spec.dst; old != nil {
			old.Dispose()
		}
		*spec.dst = f
	}
	return nil
}

// scaleFonts keeps the ramp in step with the window: a one-percent change is
// invisible, so it is not worth recreating eighteen faces for it.
func (u *natUI) scaleFonts(zoom float64) {
	if u.fontK > 0 && math.Abs(zoom-u.fontK) < 0.02 {
		return
	}
	if err := u.rebuildFonts(zoom); err != nil {
		u.fontK = zoom // do not retry every frame
	}
}

// syncPanics counts recovered callback panics so a broken worker reports once
// instead of flooding the panel.
var syncPanics int

func (u *natUI) sync(f func()) {
	if u.cw == nil {
		return
	}
	u.mw.Synchronize(func() {
		// A worker hands its result back through here. A panic inside the
		// callback would otherwise unwind the message loop and take the whole
		// process with it — the "it just closed by itself" report. Recover, log
		// once, and keep the session alive: whatever the callback failed to
		// apply is one stale value, not a lost connection.
		defer func() {
			if rec := recover(); rec != nil {
				syncPanics++
				if syncPanics <= 5 {
					u.appendLog(fmt.Sprintf("后台回调异常（已跳过该次更新）: %v", rec), 2, false, false)
					u.invalidate()
				}
			}
		}()
		f()
	})
}

func (u *natUI) invalidate() {
	if u.cw != nil {
		_ = u.cw.Invalidate()
	}
}

// ---------------------------------------------------------------------------
// DPI + dark title bar (lazy DLL, no CGO)
// ---------------------------------------------------------------------------

func enableDPIAwareness() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SetProcessDpiAwarenessContext")
	for _, c := range []uintptr{^uintptr(3), ^uintptr(2)} { // -4, -3
		if r, _, _ := proc.Call(c); r != 0 {
			return
		}
	}
	user32.NewProc("SetProcessDPIAware").Call()
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

// controlLoop re-reads the published stop list while the window is open: a
// session running when its code gets stopped is torn down on the next tick,
// not on the next restart.
func (u *natUI) controlLoop() {
	t := time.NewTicker(controlCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
			u.sync(func() { u.startControlCheck(false) })
		}
	}
}

// startControlCheck runs on the GUI thread: it touches the model, then hands
// the fetch to a worker that reports back through sync. manual is the About
// page's button — only a manual check reports an unreachable list, because a
// periodic one saying "still offline" every quarter hour is just noise.
func (u *natUI) startControlCheck(manual bool) {
	if !u.controlChecking.CompareAndSwap(false, true) {
		return
	}
	u.m.controlBusy = true
	u.invalidate()
	code := u.m.set.ControlCode
	prev := u.m.control
	go func() {
		st := evaluateControl(u.ctx, code, prev)
		u.sync(func() {
			u.controlChecking.Store(false)
			u.m.controlBusy = false
			wasStopped := u.m.control.Stopped
			u.m.control = st
			if err := saveControlState(st); err != nil {
				u.addLog(tr("远程控制状态保存失败")+": "+err.Error(), true)
			}
			switch {
			case st.Stopped && !wasStopped:
				u.addLog(tr("远程控制：本机控制码已被停用"), true)
				if u.m.connected && !u.m.working {
					u.doDisconnect()
				}
				u.controlStoppedDialog()
			case st.Stopped:
				// Already known: keep a live session down, but do not repeat
				// the dialog on every tick.
				if u.m.connected && !u.m.working {
					u.doDisconnect()
				}
				if manual {
					u.controlStoppedDialog()
				}
			case manual && !st.Reached:
				u.addLog(tr("远程控制：停用名单不可达（网络受限），沿用上次结果"), true)
			case manual:
				u.addLog(tr("远程控制：控制码正常"), false)
			}
			u.invalidate()
		})
	}()
}

// guardLogLoop mirrors the detached health guard's findings into the log panel.
// The guard is a separate process whose stderr lands in xehn.log, not in this
// window's in-memory log; without this mirror a guard-driven repair or give-up
// flips the home tile to "disconnected" with no explanation on screen (the
// "connected then disconnected, but the log says nothing" report). Only lines
// the guard tags with [guard] are surfaced, so the GUI's own file output and the
// core's chatter are not duplicated here.
func (u *natUI) guardLogLoop() {
	home, err := appDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, "xehn.log")
	var offset int64
	if fi, serr := os.Stat(path); serr == nil {
		offset = fi.Size()
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			continue
		}
		fi, serr := f.Stat()
		if serr != nil {
			f.Close()
			continue
		}
		if fi.Size() < offset {
			offset = 0 // truncated or rotated
		}
		if fi.Size() == offset {
			f.Close()
			continue
		}
		if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
			f.Close()
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		f.Close()
		// Consume only complete lines so a line being appended concurrently is
		// not split across two ticks.
		end := strings.LastIndexByte(string(data), '\n')
		if end < 0 {
			continue
		}
		offset += int64(end + 1)
		for _, line := range strings.Split(string(data[:end+1]), "\n") {
			line = strings.TrimRight(line, "\r")
			i := strings.Index(line, "[guard]")
			if i < 0 {
				continue
			}
			txt := strings.TrimSpace(line[i+len("[guard]"):])
			if txt == "" {
				continue
			}
			bad := strings.Contains(txt, "失败") || strings.Contains(txt, "断开") ||
				strings.Contains(txt, "无法") || strings.Contains(txt, "结束会话")
			u.sync(func() { u.addLog("守护："+txt, bad) })
		}
	}
}

func (u *natUI) statusLoop() {
	// A killed client, a crash or a reboot leaves connected:true plus the
	// PREVIOUS exit IP/country in state.json. The first tick would otherwise
	// paint that stale (often US) exit for seconds before the idle probe
	// corrects it — the "starts as America, then shows the local IP" report.
	// A live mihomo answers its local API instantly; if it does not, there is
	// no session to display. Do this once at startup, not on every tick.
	if st, err := loadState(); err == nil && st.Connected {
		if _, _, terr := core.Traffic(st.APIPort); terr != nil {
			st.Connected = false
			st.ExitIP, st.Country, st.Colo, st.NodeCity = "", "", "", ""
			st.CorePID, st.PsiphonPID = 0, 0
			_ = saveState(st)
		}
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var blocker string
	localTick := 0
	var lip, lcc, lcity string
	// Consecutive failed tunnel probes. An endpoint DPI tears down
	// mid-session leaves a Connected light over a dark tunnel — the exact
	// "shows connected but every page fails" state this client must never
	// show. Three misses in a row (≥6s, and each probe already waits 8s on
	// a hanging tunnel) is death; one slow answer must not trip it.
	tunnelFails := 0
	const tunnelFailLimit = 3
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		epoch := u.stateEpoch.Load()
		st, err := loadState()
		if err != nil {
			st = clientState{}
		}
		// The proxy-blocked banner names the usual suspect once, off the GUI
		// thread; the result outlives the loop variable.
		if st.ProxyWarn != "" && !u.m.blockerChecked {
			u.m.blockerChecked = true
			blocker = core.DetectProxyBlocker()
		}
		var exIP, cc, colo, city string
		var lat int64 = -1
		var up, down int64 = -1, -1
		if st.Connected {
			// Start from the persisted values and only override with fields the
			// probe actually returned: a CN egress gets 403/empty JSON from
			// speed.cloudflare.com/meta, and blanking the country/colo that the
			// connect itself verified makes them flicker off right after
			// "Connected" appears.
			exIP, cc, colo, city = st.ExitIP, st.Country, st.Colo, st.NodeCity
			if st.OpenVPNMode && st.OpenVPNNode != nil {
				// The relay is the egress; the carrier's WARP country is not.
				// Older sessions saved that carrier country into Country, so
				// the node's ISO code is the only trustworthy flag source.
				if ncc := strings.ToUpper(st.OpenVPNNode.CountryShort); ncc != "" {
					cc = ncc
				}
				colo, city = "", ""
			}
			if probe, perr := fetchSessionProbe(st.MixedPort, st.Family); perr == nil {
				tunnelFails = 0
				if probe.ExitIP != "" {
					exIP = probe.ExitIP
				}
				if probe.Country != "" {
					cc = probe.Country
				}
				if probe.Colo != "" {
					colo = probe.Colo
				}
				if probe.NodeCity != "" {
					city = probe.NodeCity
				}
			} else {
				tunnelFails++
			}
			if d, err := core.ProxyDelay(st.APIPort, "WARP", "http://www.gstatic.com/generate_204"); err == nil {
				lat = d
			}
			if u2, d2, err := core.Traffic(st.APIPort); err == nil {
				up, down = u2, d2
			}
			// Ownership decides who is allowed to repair, and it is decided by
			// the claim: this GUI only gets it when nobody else holds it -
			// which in practice means the detached guard from a CLI connect
			// keeps the job it already has, and this window stays a watcher.
			// Only a session with no living owner (the guard killed outright,
			// then no process caught it) leaves the claim free for this tick.
			// "Auto repair" is the user's switch over all of this: off means the
			// session is left alone, and this window does not even claim it, so
			// nobody else stands aside for a window that has opted out.
			ownsHealth := false
			if u.m.set.AutoRepair {
				ownsHealth = claimHealthOwner(os.Getpid())
			}

			// Tunnel death: the state says Connected but the data plane has
			// not answered three probes in a row. Repair it first - rotate to
			// another cached endpoint - and only stop when nothing left can
			// carry traffic. Disconnecting used to be the first move, which
			// put every repair on the user as another click, and the same dead
			// endpoint answered that click because only a failing verify ever
			// marked it dead. Never fires while a connect/disconnect/switch is
			// in flight: those own the state. Never fires unowned either -
			// another process already owns repair, and doing it anyway is how
			// two schedules end up killing each other's cores.
			if tunnelFails >= tunnelFailLimit && ownsHealth && !u.m.working && !u.m.connecting && u.repairing.CompareAndSwap(false, true) {
				tunnelFails = 0
				openvpnSession := st.OpenVPNMode
				u.sync(func() {
					if openvpnSession {
						u.addLog("数据面无响应（VPN Gate 出口失效）：正在更换出口节点…", true)
					} else {
						u.addLog("数据面无响应（端点已失效）：正在自动切换到备用端点…", true)
					}
				})
				go func(st clientState) {
					defer u.repairing.Store(false)
					logf := func(s string) {
						u.sync(func() { u.addLog(s, false) })
					}
					var (
						newState clientState
						ok       bool
					)
					if st.OpenVPNMode {
						// Relay first: a VPN Gate node churns far faster than the
						// WARP underlay, and rotating the underlay would silently
						// drop the exit the user chose.
						newState, ok = repairOpenVPNOnce(u.ctx, st, logf)
					} else {
						opts := optionsFromState(st)
						tried := map[string]bool{}
						newState, ok = repairOnce(u.ctx, opts, st.Endpoint, tried, logf)
						if !ok {
							// Every cached candidate failed too: the cache is
							// stale as a whole. One fresh scan, then admit defeat.
							logf("缓存端点全部失活，重新扫描…")
							opts.scanNow = true
							newState, ok = repairOnce(u.ctx, opts, st.Endpoint, tried, logf)
						}
					}
					if ok {
						u.sync(func() {
							u.stateEpoch.Add(1)
							u.m.status = newState
							u.m.connected = true
							u.addLog("已自动恢复：新端点 "+newState.Endpoint, false)
							u.invalidate()
						})
						return
					}
					giveUp(logf)
					u.sync(func() {
						u.stateEpoch.Add(1)
						u.m.connected = false
						u.m.connecting = false
						u.m.working = false
						if st2, lerr := loadState(); lerr == nil {
							u.m.status = st2
						}
						u.addLog("隧道已断开：代理已恢复、核心已停止。请重新点击连接", true)
						u.invalidate()
					})
				}(st)
			}
		} else {
			tunnelFails = 0
			// Idle: the tiles show the machine itself. Latency is a direct
			// TCP handshake; the public geo probe is throttled once it has an
			// answer (every 15th tick ≈ 30s) but retries briskly until the
			// first success, so a failed first lookup does not blank the tile
			// for half a minute.
			lat = directLatency()
			interval := 15
			if lip == "" {
				interval = 3
			}
			if localTick%interval == 1 {
				if ip, cc, city, err := fetchLocalProbe(); err == nil {
					lip, lcc, lcity = ip, cc, city
				}
			}
			localTick++
		}
		u.sync(func() {
			if u.stateEpoch.Load() != epoch {
				// A connect/disconnect/repair landed while this tick was
				// probing; its snapshot is older than the state already shown.
				return
			}
			// Persist a CONFIRMED exit once, for every mode (not just
			// OpenVPN). Otherwise each tick re-reads the WARP carrier's US
			// from state.json, a successful probe paints GB, and the next
			// failed probe falls back to US — the US/GB flicker.
			if st.Connected && cc != "" && st.Country != cc {
				st.Country, st.Colo, st.NodeCity, st.ExitIP = cc, colo, city, exIP
				_ = saveState(st)
			}
			st.ExitIP, st.Country, st.Colo, st.NodeCity = exIP, cc, colo, city
			u.m.status = st
			u.m.proxyBlocker = blocker
			// Keep watching the host proxy for the whole session. Another client
			// (v2rayN rewrites WinINET on its own timer) can take it away minutes
			// after connect; the tunnel stays up, the window keeps saying 已连接,
			// and every browser goes out directly — the user believes they are on
			// Psiphon while their ISP sees the real address.
			if u.m.connected && !st.TUN && !st.NoProxy && st.MixedPort > 0 {
				if !core.SystemProxyEnabledAt(st.MixedPort) {
					if !u.m.proxyLost {
						u.m.proxyLost = true
						u.addLog(trf("系统代理已被其它程序改动，当前流量可能未经过隧道（应为 127.0.0.1:%d）", st.MixedPort), true)
					}
				} else if u.m.proxyLost {
					u.m.proxyLost = false
					u.addLog(tr("系统代理已恢复，流量重新经过隧道"), false)
				}
			} else if u.m.proxyLost {
				u.m.proxyLost = false
			}
			// While an attempt is in flight the pipeline owns this flag. A poll
			// that read state.json before the cancel landed must not flip the
			// button back to "已连接" afterwards — that is the "cancelled, then
			// suddenly connected" report.
			if !u.m.connecting && !u.m.cancelling && !u.m.working {
				u.m.connected = st.Connected
			}
			// Recompute on a slow cadence, not just when empty: a machine that
			// gains a Docker/WSL adapter mid-session would otherwise keep
			// advertising a 172.x address that no phone can reach, and a Wi-Fi
			// switch changes the answer too. Enumerating adapters is a few
			// hundred microseconds, so every 30s is free.
			if u.m.localLan == "" || localTick%15 == 0 {
				if ip := localLanIP(); ip != "" {
					u.m.localLan = ip
				}
			}
			// Periodic stale-proxy sweep. The startup heal runs while an orphan
			// core from a killed session may still hold the port, so it sees a
			// listener and backs off; that core then dies and the host proxy is
			// left pointing at nothing. Re-checking once a minute while idle
			// catches that window without ever touching a live session.
			if time.Since(u.lastHealAt) > time.Minute &&
				!u.m.connected && !u.m.connecting && !u.m.working {
				u.lastHealAt = time.Now()
				port := u.m.set.MixedPort
				go func() {
					if healProxyIfStale(port) {
						u.sync(func() {
							u.addLog(trf("已清理残留的系统代理（127.0.0.1:%d，端口已无监听）", port), false)
						})
					}
				}()
			}
			if lip != "" {
				u.m.localIP, u.m.localCC, u.m.localCity = lip, lcc, lcity
			}
			if lat >= 0 {
				u.m.latency = lat
				u.m.samples = append(u.m.samples, lat)
				if len(u.m.samples) > 120 {
					u.m.samples = u.m.samples[len(u.m.samples)-120:]
				}
			}
			if up >= 0 && down >= 0 {
				u.m.upRates = append(u.m.upRates, up)
				u.m.downRates = append(u.m.downRates, down)
				if len(u.m.upRates) > 120 {
					u.m.upRates = u.m.upRates[len(u.m.upRates)-120:]
				}
				if len(u.m.downRates) > 120 {
					u.m.downRates = u.m.downRates[len(u.m.downRates)-120:]
				}
				if up > u.m.peakUp {
					u.m.peakUp = up
				}
				if down > u.m.peakDown {
					u.m.peakDown = down
				}
			}
			if !st.Connected && (len(u.m.upRates) > 0 || len(u.m.downRates) > 0) {
				u.m.upRates, u.m.downRates = nil, nil
				u.m.peakUp, u.m.peakDown = 0, 0
				u.m.sessionUp, u.m.sessionDown = 0, 0
				u.m.shareBytes = [5]int64{}
				u.m.shareTotal = 0
			}
			// Never clobber the busy flag while a connect/disconnect is in
			// flight: first-use connects spend minutes scanning, and wiping
			// the spinner every poll made the button look dead and allowed
			// double-clicks to start overlapping connects.
			if !st.Connected && !u.m.working {
				u.m.connecting = false
			}
			u.invalidate()
		})
	}
}

func (u *natUI) spinLoop() {
	// 16ms (~60fps) drives the connect button while a connect/disconnect is in
	// flight, and the page-switch slide. On the home page the hexagon's slow
	// breathing glow (2.2-4.5s cycles) only needs ~7.5fps (every 8th tick), so
	// idle repaints cost half what they did at 15fps on old machines; other
	// pages cost nothing when nothing animates.
	t := time.NewTicker(16 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		u.sync(func() {
			// A minimised or hidden window cannot show a frame, so nothing below
			// is worth painting. The spin counter still advances so the glow and
			// spinners resume mid-cycle when the window comes back.
			hidden := u.windowHidden()
			if u.m.connecting || u.m.working {
				u.m.spin++
				if hidden {
					return
				}
				u.invalidate()
				return
			}
			// The subscription latency test turns a per-node spinner; ~20fps
			// (every 3rd tick) is smooth enough and only runs while testing.
			if u.m.page == pageNodes && u.subDelayBusy.Load() {
				u.m.spin++
				if u.m.spin%3 == 0 && !hidden {
					u.invalidate()
				}
				return
			}
			if u.m.page == "home" {
				u.m.spin++
				if u.m.spin%8 == 0 && !hidden {
					u.invalidate()
				}
				return
			}
			if time.Since(u.pageAnimAt) < 260*time.Millisecond && !hidden {
				u.invalidate()
			}
		})
	}
}

// windowHidden reports a minimised or hidden window. Painting a window nobody
// can see is the last idle cost worth removing: the home page repaints ~7.8fps
// for its breathing glow and the connect button runs at 60fps, which a
// background client should not pay.
func (u *natUI) windowHidden() bool {
	if u.mw == nil || !u.mw.Visible() {
		return true
	}
	h := u.mw.Handle()
	if h == 0 {
		return true
	}
	r, _, _ := proc("IsIconic").Call(uintptr(h))
	return r != 0
}

func (u *natUI) reloadEndpoints(force bool) {
	proto := u.m.proto
	outer, inner := u.m.outerProto, u.m.innerProto
	if force {
		go func() {
			if !u.rescanBusy.CompareAndSwap(false, true) {
				u.sync(func() { u.addLog(tr("已有扫描在进行中，忽略重复点击"), false) })
				return
			}
			defer u.rescanBusy.Store(false)
			opts := defaultConnectOptions(proto, false, true)
			if proto == protoWWarp {
				// Mirror runConnectCmd's chain normalisation: a wwarp scan is
				// the inner scan through an auto-picked outer endpoint, never
				// a scan of "wwarp" as a wire protocol.
				opts.outerProto = outer
				opts.innerProto = inner
				if err := ensureAccount(u.ctx, opts); err != nil {
					u.sync(func() {
						u.addLog("账号加载失败: "+err.Error(), true)
						u.invalidate()
					})
					return
				}
				u.sync(func() { u.addLog("[WARP-in-WARP] 选择外层端点…", false) })
				endpoint, err := pickOuterEndpoint(u.ctx, opts)
				if err != nil {
					u.sync(func() {
						u.addLog("外层端点获取失败: "+err.Error(), true)
						u.invalidate()
					})
					return
				}
				opts.through = endpoint
				opts.proto = opts.outerProto
				u.sync(func() {
					u.addLog(fmt.Sprintf("[WARP-in-WARP] 外层端点 %s，扫描内层端点…", endpoint), false)
				})
			}
			u.sync(func() { u.addLog("重新扫描 WARP 端点（可能需要 1-2 分钟）…", false) })
			_, _, err := runCachedScan(u.ctx, opts)
			u.sync(func() {
				if err != nil {
					u.addLog("扫描失败: "+err.Error(), true)
				} else {
					u.addLog("扫描完成", false)
				}
				u.applyEndpoints(proto)
				u.invalidate()
			})
		}()
		return
	}
	u.applyEndpoints(proto)
}

// refreshVPNGatePool reloads the VPN Gate country list for the OpenVPN region
// dropdown. The cached list answers immediately; a stale or empty cache is
// refreshed off-thread. The fetch tries direct HTTPS, then the live mixed port,
// then a throwaway WARP tunnel — the last one is what makes the list work on
// networks that block vpngate.net (and when the selected WARP endpoint died).
// force (optional) skips the cache age check, for the popup's retry action.
func (u *natUI) refreshVPNGatePool(force ...bool) {
	if u.m.vpnPoolBusy {
		if len(force) > 0 && force[0] {
			u.addLog(tr("VPN Gate 节点正在刷新中…"), false)
			u.invalidate()
		}
		return
	}
	forced := len(force) > 0 && force[0]
	nodes, at := loadVPNGateCache()
	stale := forced || len(nodes) == 0 || time.Since(at) >= vpnGateCacheTTL
	if len(nodes) > 0 {
		u.m.vpnNodes = nodes
		u.m.vpnCountries = vpnGateCountries(nodes)
	}
	if !stale {
		u.invalidate()
		return
	}
	u.m.vpnPoolBusy = true
	u.m.vpnPoolNote = tr("正在获取 VPN Gate 节点…")
	u.addLog(tr("正在获取 VPN Gate 节点…"), false)
	u.invalidate()
	go func() {
		fresh, route, err := u.fetchVPNGatePool()
		if len(fresh) > 0 {
			saveVPNGateCache(fresh)
		}
		u.sync(func() {
			u.m.vpnPoolBusy = false
			switch {
			case len(fresh) > 0:
				u.m.vpnNodes = fresh
				u.m.vpnCountries = vpnGateCountries(fresh)
				// A refresh is a pure list fetch: rows stay 未检测 until the
				// user presses 延迟测试. No TCP probe runs here.
				u.m.vpnMeasured = false
				u.m.vpnPoolNote = ""
				u.addLog(trf("VPN Gate 节点获取成功：%d 个节点，%d 个国家（%s）",
					len(fresh), len(u.m.vpnCountries), tr(route)), false)
			case len(u.m.vpnNodes) == 0:
				if err != nil {
					u.m.vpnPoolNote = trf("节点列表获取失败：%s（点击重试）", vpnShortErr(err))
					u.addLog(trf("VPN Gate 节点获取失败：%s", vpnShortErr(err)), true)
				} else {
					u.m.vpnPoolNote = tr("节点列表获取失败：请点击重试")
					u.addLog(tr("VPN Gate 节点获取失败：节点列表为空"), true)
				}
			default:
				// Keep the stale countries usable; the note is only shown when
				// the popup has nothing else to display.
				u.m.vpnPoolNote = ""
				if err != nil {
					u.addLog(trf("VPN Gate 节点刷新失败：%s（沿用缓存列表）", vpnShortErr(err)), true)
				}
			}
			u.invalidate()
		})
	}()
}

// loadVPNGateCacheOnly fills the picker from the on-disk cache. No network
// request, no classification lookup and no TCP probe: startup, switch toggle
// and opening the region picker must never fetch or measure anything. Only the
// 刷新 button may fetch live data, and only 延迟测试 may measure a node.
func (u *natUI) loadVPNGateCacheOnly() {
	nodes, _ := loadVPNGateCache()
	if len(nodes) == 0 {
		return
	}
	u.m.vpnNodes = nodes
	u.m.vpnCountries = vpnGateCountries(nodes)
	// A fresh read carries no measurements: rows show 未检测 until the user
	// runs the manual OpenVPN handshake/speed test.
	u.m.vpnMeasured = false
}

// fetchVPNGatePool pulls the node list and classifies it off the GUI thread.
// It deliberately does NOT measure latency: a refresh is a pure list fetch.
// The only latency/speed numbers shown are real OpenVPN handshake + download
// results produced by the manual 延迟测试 button.
func (u *natUI) fetchVPNGatePool() ([]vpnGateNode, string, error) {
	directErr := error(nil)
	if raw, err := fetchVPNGateDirect(u.ctx); err == nil {
		if nodes := parseVPNGateCSV(raw); len(nodes) > 0 {
			u.classifyVPNGatePool(nodes, nil)
			sortVPNGateNodesByLatency(nodes)
			return nodes, "直连", nil
		}
		directErr = fmt.Errorf("VPN Gate 返回的列表为空")
	} else {
		directErr = err
	}

	proxyErr := directErr
	if st, lerr := loadState(); lerr == nil && st.Connected && st.MixedPort > 0 {
		if raw, perr := fetchVPNGateViaProxy(u.ctx, st.MixedPort); perr == nil {
			if nodes := parseVPNGateCSV(raw); len(nodes) > 0 {
				u.classifyVPNGatePool(nodes, vpnGateProxyClient(st.MixedPort, 15*time.Second))
				sortVPNGateNodesByLatency(nodes)
				return nodes, "本机代理", nil
			}
		} else {
			proxyErr = perr
		}
	}

	// Subscription mode has no WARP tunnel to fall back on, and building one
	// here would contradict the mode. The honest fallback is the mode's own
	// first hop: fetch through the imported node the session would use. Without
	// this, a network that blocks vpngate.net directly left subscription mode
	// with no way to refresh the exit pool at all ("无法拉取节点").
	if u.m.set.ConnMode == "subscription" {
		u.sync(func() {
			u.m.vpnPoolNote = tr("直连不可用，正在经订阅节点获取节点…")
			u.addLog(tr("直连不可用，正在经订阅节点获取节点…"), false)
			u.invalidate()
		})
		var lastErr error
		fronts := subscriptionFronts(u.m.set)
		for i, front := range fronts {
			if i > 0 {
				prev := fronts[i-1]
				u.sync(func() {
					u.addLog(trf("前置节点 %s 不可用，换下一个…", prev), false)
					u.invalidate()
				})
			}
			nodes, serr := fetchVPNGateViaSubscription(u.ctx, u.m.set.CustomProxies, front)
			if serr == nil {
				return nodes, "订阅节点", nil
			}
			lastErr = serr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("没有可用于抓取的订阅节点")
		}
		return nil, "", fmt.Errorf("%s；订阅节点: %s", vpnShortErr(directErr), vpnShortErr(lastErr))
	}
	u.sync(func() {
		u.m.vpnPoolNote = tr("直连不可用，正在经 WARP 获取节点…")
		u.addLog(tr("直连不可用，正在经 WARP 获取节点…"), false)
		u.invalidate()
	})
	nodes, werr := u.fetchVPNGatePoolViaWARP()
	if werr != nil {
		return nil, "", fmt.Errorf("%s；WARP: %s", vpnShortErr(proxyErr), vpnShortErr(werr))
	}
	return nodes, "WARP 隧道", nil
}

// classifyVPNGatePool runs the two-source IP classification. proxyClient is
// non-nil when the pool itself was fetched through the local proxy.
func (u *natUI) classifyVPNGatePool(nodes []vpnGateNode, proxyClient *http.Client) {
	u.sync(func() { u.m.vpnPoolNote = tr("正在识别家宽/机房节点…") })
	client := proxyClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	enrichCtx, cancel := context.WithTimeout(u.ctx, 25*time.Second)
	defer cancel()
	_, _ = enrichVPNGateClasses(enrichCtx, client, nodes)
}

// fetchVPNGatePoolViaWARP builds a throwaway tunnel on the protocol the user
// actually connects with and fetches through it. The endpoint preference is the
// user's selected endpoint first, then the last endpoint that ever worked, then
// the cached scan — a half-dead selection costs one handshake, not the fetch.
func (u *natUI) fetchVPNGatePoolViaWARP() ([]vpnGateNode, error) {
	underlay := u.m.proto
	if protoChained(underlay) {
		underlay = protoAWG
	}
	switch underlay {
	case protoWG, protoAWG, protoMASQUE, protoMASQUEH2:
	default:
		underlay = protoAWG
	}
	opts := defaultConnectOptions(underlay, false, false)
	if err := ensureAccount(u.ctx, opts); err != nil {
		return nil, err
	}
	var results []cachedEndpoint
	if cs, ok := cachedScanFor(underlay, scanFamilyV6()); ok {
		results = cs.Results
	}
	prefer := u.m.pin
	if st, err := loadState(); err == nil && st.Endpoint != "" && prefer == "" && st.Proto == underlay {
		prefer = st.Endpoint
	}
	run := mustParseProto(underlay)
	if len(results) == 0 {
		// No scan cache to fall back on. Try the remembered endpoint first —
		// it is usually still alive and a scan costs one to two minutes — but a
		// dead selection must not end the fetch: scan and try again instead.
		quickErr := error(nil)
		if prefer != "" || loadVPNGateUnderlay() != "" {
			if nodes, err := fetchVPNGateNodesViaWARP(u.ctx, nil, run, prefer); err == nil {
				return nodes, nil
			} else {
				quickErr = err
				// Both remembered endpoints were just proved dead; spending a
				// slot on them again after the scan would waste a third of the
				// retry budget.
				prefer = ""
			}
		}
		u.sync(func() {
			u.m.vpnPoolNote = tr("正在扫描 WARP 端点（约 1-2 分钟）…")
			u.addLog(tr("正在扫描 WARP 端点（约 1-2 分钟）…"), false)
			u.invalidate()
		})
		fresh, _, err := runCachedScan(u.ctx, opts)
		if err != nil {
			if quickErr != nil {
				return nil, fmt.Errorf("%s；扫描: %s", vpnShortErr(quickErr), vpnShortErr(err))
			}
			return nil, err
		}
		results = fresh
	}
	// Bound the whole attempt: a dead peer makes every round-trip wait for its
	// timeout, and two endpoints can hold the "正在获取" note for minutes.
	fctx, fcancel := context.WithTimeout(u.ctx, 50*time.Second)
	nodes, ferr := fetchVPNGateNodesViaWARP(fctx, results, run, prefer)
	fcancel()
	if ferr == nil {
		return nodes, nil
	}
	// The cached endpoints carried nothing. That is the normal state after the
	// network moved (or after a bad scan): a WireGuard tunnel to a dead peer
	// still "starts", so the cache keeps claiming the endpoint is working.
	// One forced rescan and one retry — this is what makes WARP mode able to
	// fetch the list again instead of reporting failure forever.
	if len(results) > 0 {
		u.sync(func() {
			u.m.vpnPoolNote = tr("缓存端点无法转发，重新扫描 WARP 端点（约 1-2 分钟）…")
			u.addLog(tr("缓存端点无法转发，重新扫描 WARP 端点（约 1-2 分钟）…"), false)
			u.invalidate()
		})
		scanOpts := opts
		scanOpts.scanNow = true
		fresh, _, serr := runCachedScan(u.ctx, scanOpts)
		if serr == nil && len(fresh) > 0 {
			rctx, rcancel := context.WithTimeout(u.ctx, 50*time.Second)
			nodes, rerr := fetchVPNGateNodesViaWARP(rctx, fresh, run, "")
			rcancel()
			if rerr == nil {
				return nodes, nil
			}
			return nil, fmt.Errorf("%s；重扫后仍失败: %s", vpnShortErr(ferr), vpnShortErr(rerr))
		}
		if serr != nil {
			return nil, fmt.Errorf("%s；重扫: %s", vpnShortErr(ferr), vpnShortErr(serr))
		}
	}
	return nil, ferr
}

// protoOK reports whether the installed core parses this protocol's config.
// Before the probe finishes (or with no core installed) it optimistically
// returns true: the connect pipeline runs the authoritative gate anyway.
func (u *natUI) protoOK(p string) bool {
	if !u.m.coreInstalled || u.m.capab == nil {
		return true
	}
	return u.m.capab[p]
}

// exitOK reports whether the stacked exits (Psiphon / VPN Gate) are available.
// Subscription mode has no WARP tunnel — the imported node is the underlay —
// so the leftover WARP protocol choice must not veto the exits there. WARP
// mode still excludes chained protocols, whose nested tunnel cannot carry a
// third hop.
func (u *natUI) exitOK() bool {
	return u.m.set.ConnMode == "subscription" || !protoChained(u.m.proto)
}

// exitV6OK reports whether an exit can work on an IPv6-only tunnel. Neither
// exit can: VPN Gate relays are IPv4-only (and mihomo's openvpn outbound cannot
// carry a v6 tunnel at all), and Psiphon's own servers are reached over IPv4.
// A v6-only tunnel has no route to either target, so the switches are disabled
// instead of being left to fail after a 30-second connect attempt.
func (u *natUI) exitV6OK() bool {
	return u.m.set.IPFamily != famV6
}

// probeCore stats the core binary and, when present, asks it which protocols
// it can actually parse (`mihomo -t` on a minimal config per protocol). The
// result drives the protocol tiles (unsupported ones are visibly marked) and
// the version line. Runs off the GUI thread; probeCoreCapabilities caches, so
// repeat calls are cheap.
// coreMissingHint explains a missing core in terms the user can act on: the
// two causes look identical in a log line but need different fixes.
func coreMissingHint(dir, bin string) string {
	if _, err := os.Stat(dir); err != nil {
		return tr("内核缺失：当前目录下没有 core 文件夹。请解压整个压缩包后再运行 xehn.exe（不要只把 exe 单独拿出来）。")
	}
	if fi, err := os.Stat(bin); err == nil && fi.Size() == 0 {
		return tr("内核文件 core\\mihomo.exe 是 0 字节（下载或解压中断），请删掉它后用底栏「核心」按钮重新下载。")
	}
	return tr("内核缺失：core\\mihomo.exe 不存在。多数情况是被杀毒软件隔离，请把 XEHN 目录加入白名单后，用底栏「核心」按钮重新下载。")
}

func (u *natUI) probeCore() {
	dir, err := coreDir()
	if err != nil {
		return
	}
	u.sync(func() { u.refreshCoreCard(dir) })
	bin := core.CoreInDir(dir)
	if fi, err := os.Stat(bin); err != nil || fi.Size() == 0 {
		// Say which of the two very different problems this is. "Core missing"
		// has two causes that need opposite fixes: the user ran the bare exe
		// without the rest of the archive, or a security product removed
		// mihomo.exe after extraction.
		u.sync(func() {
			u.addLog(coreMissingHint(dir, bin), true)
		})
		return
	}
	ver, supported, perr := probeCoreCapabilities(bin, dir)
	u.sync(func() {
		u.m.coreVersion = ver
		u.m.capab = supported
		if perr != nil {
			u.addLog("Core 能力探测失败: "+perr.Error(), true)
			// A file that exists but cannot be executed is almost always a
			// security product or Smart App Control, not a broken download.
			// Give the exact recovery steps instead of the generic "请升级核心".
			u.addLog(tr("核心文件存在却无法运行时：请把 XEHN 目录加入杀毒软件白名单；右键 xehn.exe 与 core\\mihomo.exe → 属性 → 勾选「解除锁定」；Windows 安全中心检查「智能应用控制」是否拦截。完成后重启程序"), true)
		} else {
			var ok []string
			for _, r := range protoRuns {
				if supported[r.name] {
					ok = append(ok, protoLabel(r.name))
				}
			}
			u.addLog("Core "+ver+" 就绪，支持协议: "+strings.Join(ok, "、"), false)
		}
		u.invalidate()
	})
}

func (u *natUI) applyEndpoints(proto string) {
	cs, ok := cachedScanFor(proto, scanFamilyV6())
	if !ok || len(cs.Results) == 0 {
		u.m.endpoints = nil
		u.m.scanFresh = false
		return
	}
	u.m.endpoints = cs.Results
	u.m.scanAt = cs.At
	u.m.scanFresh = time.Since(cs.At) < scanTTL
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

// retryProxySet re-runs the host-side WinINET edit for a live connect whose
// first attempt security software blocked — the user has typically just added
// the client to the suite's trust list. The tunnel itself was already verified
// by the connect, so this only touches the proxy values and the state file.
func (u *natUI) retryProxySet() {
	st, err := loadState()
	if err != nil || !st.Connected || st.MixedPort == 0 {
		return
	}
	u.sync(func() { u.addLog("重新设置系统代理…", false) })
	snap, err := core.SetSystemProxy(st.MixedPort)
	if err != nil && proxyHelperAllowed() {
		u.sync(func() { u.addLog("请求管理员授权设置系统代理（仅本次需要 UAC 确认）…", false) })
		if herr := core.SetSystemProxyElevated(st.MixedPort); herr == nil {
			err = nil
		}
	}
	if err != nil {
		u.sync(func() { u.addLog("系统代理仍被拦截: "+err.Error(), true) })
		return
	}
	if raw, jerr := json.Marshal(snap); jerr == nil {
		st.ProxySnap = raw
	}
	st.ProxyWarn = ""
	if serr := saveState(st); serr != nil {
		u.sync(func() { u.addLog("状态保存失败: "+serr.Error(), true) })
		return
	}
	u.sync(func() { u.addLog("系统代理设置成功", false) })
}

func (u *natUI) addLog(text string, err bool) {
	lv := 0
	if err {
		lv = 2
	}
	u.addLogFull(text, lv, false)
}

// addLogFull appends one line to the log panel.
func (u *natUI) addLogFull(text string, lv int, core bool) {
	u.appendLog(text, lv, core, false)
}

// addLogStage records a line produced by the connection pipeline itself. Those
// lines are the "sessions" view: attempts, endpoint choice, failure and
// disconnect, without the core's own chatter.
func (u *natUI) addLogStage(text string) { u.appendLog(text, 0, false, true) }

// Log retention. The client's own lines are never dropped — a failed connect is
// diagnosed from them and they arrive at human pace. The core's chatter is what
// floods: mihomo logs every connection, rule match and DNS lookup, so an
// unbounded panel grew without limit on a long session (the "memory climbs and
// the UI freezes" report). maxLogLines is the hard ceiling on the whole panel;
// maxCoreLogLines is the budget core lines get when a trim happens, so the
// client's own session lines survive a flood.
const (
	maxCoreLogLines = 3000
	maxLogLines     = 20000
	trimLogTarget   = 12000
)

func (u *natUI) appendLog(text string, lv int, core, stage bool) {
	u.m.logs = append(u.m.logs, natLog{at: time.Now(), text: text, lv: lv, core: core, stage: stage})
	if len(u.m.logs) > maxLogLines {
		u.trimLogs()
	}
}

// trimLogs keeps the newest lines, giving core chatter at most half the budget
// so the client's own session lines survive a flood. It runs only once the
// panel passes the hard ceiling, so the scan is amortised over thousands of
// appends rather than paid per line.
func (u *natUI) trimLogs() {
	coreBudget := maxCoreLogLines
	out := make([]natLog, 0, trimLogTarget)
	for i := len(u.m.logs) - 1; i >= 0 && len(out) < trimLogTarget; i-- {
		l := u.m.logs[i]
		if l.core {
			if coreBudget == 0 {
				continue
			}
			coreBudget--
		}
		out = append(out, l)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	u.m.logs = out
}

// logText renders every retained line for the clipboard and diagnostics. The
// panel shows one screenful at a time; copying must not inherit that limit.
func (u *natUI) logText() string {
	var b strings.Builder
	for _, l := range u.m.logs {
		b.WriteString(l.at.Format("2006-01-02 15:04:05 "))
		switch {
		case l.lv == 2:
			b.WriteString("ERR  ")
		case l.lv == 1:
			b.WriteString("WARN ")
		case l.core:
			b.WriteString("CORE ")
		default:
			b.WriteString("INFO ")
		}
		b.WriteString(l.text)
		b.WriteString("\r\n")
	}
	return b.String()
}

// setClipboardText retries the hand-off: a screenshot tool or clipboard manager
// can hold the clipboard open for a few dozen milliseconds, and a one-shot
// SetText then fails while the previous content (often an image) stays behind.
// Clearing first matters too: walk sets only CF_UNICODETEXT, and leftover
// formats from a screenshot otherwise survive and paste back as an image.
func setClipboardText(text string) error {
	var err error
	for i := 0; i < 8; i++ {
		if err = walk.Clipboard().Clear(); err != nil {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		if err = walk.Clipboard().SetText(text); err == nil {
			return nil
		}
		time.Sleep(30 * time.Millisecond)
	}
	return err
}

func (u *natUI) action(id string) {
	m := u.m
	switch {
	case id == "connect":
		if m.connecting {
			// Cancelling is the only sensible meaning of the click while the
			// pipeline runs; swallowing it made the button look dead.
			u.cancelConnect()
			return
		}
		if m.connected {
			u.doDisconnect()
		} else {
			u.doConnect()
		}
	case strings.HasPrefix(id, "proto:"):
		p := strings.TrimPrefix(id, "proto:")
		m.dropOpen = ""
		if p != m.proto {
			// Capability gate: never switch to (let alone render) a protocol
			// the installed core cannot parse — say so instead.
			if !u.protoOK(p) {
				u.addLog(trf("当前 Core 不支持 %s 协议，请升级 Core（Mihomo 官方最新版）", protoLabel(p)), true)
				return
			}
			m.proto = p
			m.pin = ""
			// Nested protocols cannot carry IPv6 (inner MTU is below the v6
			// minimum), so the family follows the capability down to v4 rather
			// than letting the page offer a choice the renderer would ignore.
			// Subscription mode has no WARP tunnel, so the gate skips it.
			if m.set.ConnMode != "subscription" && !protoV6Capable(p) && m.set.IPFamily != famV4 {
				u.mutateSettings(func(s *clientSettings) {
					s.IPFamily = famV4
					s.Pin = ""
				})
			}
			m.scroll = 0
			u.reloadEndpoints(false)
			u.invalidate()
			// Hot switch: a live connection swaps protocols without making
			// the user disconnect by hand first.
			if m.connected {
				u.doSwitch()
			}
		}
	case id == "psiphon":
		if !u.exitV6OK() {
			u.addLog(tr("仅 IPv6 模式下不能启用出口：Psiphon 服务器经 IPv4 出网"), true)
			return
		}
		m.psiphon = !m.psiphon
		// The two exits replace the same thing; enabling one turns the other
		// off instead of letting a file/UI carry both.
		if m.psiphon {
			m.openvpn = false
			// The stacked exit is v4-only. Clamp the live family now:
			// saveSettings normalizes a copy, so without this the in-memory
			// selector would keep offering a v6 the session cannot carry.
			if m.set.IPFamily != famV4 {
				m.pin = ""
				u.mutateSettings(func(s *clientSettings) {
					s.IPFamily = famV4
					s.Pin = ""
				})
			}
		}
		u.invalidate()
		// Hot switch, like the protocol chips: a live connection swaps its exit
		// without making the user disconnect by hand first.
		if m.connected && u.exitOK() && !m.working && !m.connecting {
			u.doSwitch()
		}
	case id == "openvpn":
		if !u.exitOK() || !u.exitV6OK() {
			return
		}
		m.openvpn = !m.openvpn
		if m.openvpn {
			m.psiphon = false
			// VPN Gate is v4 end to end; clamp the family like Psiphon does.
			if m.set.IPFamily != famV4 {
				m.pin = ""
				u.mutateSettings(func(s *clientSettings) {
					s.IPFamily = famV4
					s.Pin = ""
				})
			}
		}
		u.invalidate()
		if m.openvpn {
			// Manual refresh only. Turning the switch on must not fetch the
			// pool from the network behind the user's back.
			u.loadVPNGateCacheOnly()
		}
		if m.connected && !m.working && !m.connecting {
			u.doSwitch()
		}
	case id == "drop:region", id == "drop:vpnregion", id == "drop:proto", id == "drop:family", id == "drop:preset", id == "drop:capture", id == "drop:homenode", id == "drop:connmode", id == "drop:addmenu", id == "drop:submgr":
		which := strings.TrimPrefix(id, "drop:")
		if m.dropOpen == which {
			m.dropOpen = ""
		} else {
			m.dropOpen = which
			if which == "vpnregion" {
				m.vpnScroll = 0
				// Opening the picker never refreshes the pool and never runs a
				// TCP probe. Both actions are triggered only by their buttons.
				u.loadVPNGateCacheOnly()
			}
			if which == "region" {
				m.regionScroll = 0
				u.regionEnsureSelectedVisible()
			}
			if which == "homenode" {
				m.homeNodeScroll = 0
			}
			if which == "submgr" {
				m.subMgrScroll = 0
			}
		}
		u.debugLogf(fmt.Sprintf("action %s -> dropOpen=%q page=%q", id, m.dropOpen, m.page))
		u.invalidate()
	case id == "vpnrefresh":
		u.refreshVPNGatePool(true)
	case id == "vpnprobe":
		u.runVPNProbe()
	case id == "suburl":
		m.dropOpen = ""
		u.importSubscriptionURL()
	case id == "subfile":
		m.dropOpen = ""
		u.importSubscriptionFile()
	case id == "subclip":
		m.dropOpen = ""
		u.importSubscriptionClipboard()
	case id == "subqr":
		m.dropOpen = ""
		u.importSubscriptionQR()
	case id == "subsingle":
		m.dropOpen = ""
		u.importSingleProxy()
	case id == "subrefresh":
		m.dropOpen = ""
		u.refreshSubscriptions()
	case strings.HasPrefix(id, "connmode:"):
		mode := strings.TrimPrefix(id, "connmode:")
		m.dropOpen = ""
		if mode != m.set.ConnMode && (mode == "warp" || mode == "subscription") {
			m.set.ConnMode = mode
			// The family gate depends on the mode (a subscription node carries
			// its own v6 capability): re-clamp the live copy so it matches the
			// normalized file saveSettings writes.
			m.set.normalize()
			m.pin = m.set.Pin
			if err := saveSettings(m.set); err != nil {
				u.addLog(tr("设置保存失败: ")+err.Error(), true)
			}
			label := tr("WARP 模式")
			if mode == "subscription" {
				label = tr("订阅模式")
			}
			u.addLog(tr("模式切换")+": "+label, false)
			m.scroll = 0
		}
		u.invalidate()
	case id == "submode":
		u.toggleConnMode()
	case id == "subnodes":
		// The home-page pill in subscription mode is the front-node selector:
		// the actual picking happens on the node page, which owns the grid.
		u.gotoPage(pageNodes)
	case id == "subdelay":
		u.testSubscriptionDelays()
	case id == "subauto":
		m.dropOpen = ""
		u.toggleSubAuto()
	case strings.HasPrefix(id, "subpick:"):
		m.dropOpen = ""
		u.pickSubscriptionProxy(strings.TrimPrefix(id, "subpick:"))
	case id == "subrefreshcur":
		u.refreshCurrentSub()
	case id == "submgr:import":
		u.subMgrImport()
	case strings.HasPrefix(id, "subswitch:"):
		// "" is the "全部订阅" row, so an empty suffix is a real target.
		u.switchSubscription(strings.TrimPrefix(id, "subswitch:"))
	case strings.HasPrefix(id, "subedit:"):
		u.editSubscription(strings.TrimPrefix(id, "subedit:"))
	case strings.HasPrefix(id, "subdel:"):
		u.deleteSubscription(strings.TrimPrefix(id, "subdel:"))
	case strings.HasPrefix(id, "vpncountry:"):
		cc := strings.TrimPrefix(id, "vpncountry:")
		if strings.EqualFold(m.vpnExpanded, cc) {
			m.vpnExpanded = ""
		} else {
			m.vpnExpanded = cc
			for i, row := range u.vpnPopupRows() {
				if row.kind == vpnRowCountry && row.cc == cc {
					u.vpnEnsureRowVisible(i)
					break
				}
			}
		}
		u.invalidate()
	case strings.HasPrefix(id, "pickvpnnode:"):
		nid := strings.TrimPrefix(id, "pickvpnnode:")
		node, ok := u.vpnNodeByID(nid)
		if !ok {
			return
		}
		m.dropOpen = ""
		if m.set.OpenVPNNode != nid || m.set.OpenVPNRegion != node.CountryShort {
			u.mutateSettings(func(s *clientSettings) {
				s.OpenVPNNode = nid
				s.OpenVPNRegion = node.CountryShort
			})
			if m.connected && m.openvpn && !m.working && !m.connecting {
				u.doSwitch()
			}
		}
		u.invalidate()
	case strings.HasPrefix(id, "pickvpnregion:"):
		cc := strings.TrimPrefix(id, "pickvpnregion:")
		m.dropOpen = ""
		if m.set.OpenVPNRegion != cc || m.set.OpenVPNNode != "" {
			u.mutateSettings(func(s *clientSettings) {
				s.OpenVPNRegion = cc
				s.OpenVPNNode = ""
			})
			// The region shapes only the relay: a live OpenVPN session
			// re-applies it by reconnecting.
			if m.connected && m.openvpn && !m.working && !m.connecting {
				u.doSwitch()
			}
		}
		u.invalidate()
	case strings.HasPrefix(id, "pickregion:"):
		cc := strings.TrimPrefix(id, "pickregion:")
		m.dropOpen = ""
		if m.set.PsiphonRegion != cc {
			u.mutateSettings(func(s *clientSettings) { s.PsiphonRegion = cc })
			// The region shapes only a Psiphon exit: like the exit switch, a
			// live Psiphon session re-applies it by reconnecting.
			if m.connected && m.psiphon && u.exitOK() && !m.working && !m.connecting {
				u.doSwitch()
			}
		}
		u.invalidate()
	case strings.HasPrefix(id, "pickfamily:"):
		f := strings.TrimPrefix(id, "pickfamily:")
		m.dropOpen = ""
		if f != famV4 && f != famV6 && f != famBoth {
			u.invalidate()
			return
		}
		if f != famV4 && !u.familyV6OK() {
			if m.psiphon || m.openvpn {
				u.addLog(tr("叠加出口仅支持 IPv4：请先关闭出口"), true)
			} else {
				u.addLog(trf("%s 不支持 IPv6：请先切换协议", protoDisplayName(m.proto)), true)
			}
			u.invalidate()
			return
		}
		if m.set.IPFamily != f {
			u.mutateSettings(func(s *clientSettings) { s.IPFamily = f })
			// normalize drops a pinned node that belongs to the other family.
			m.pin = m.set.Pin
		}
		u.invalidate()
	case id == "copyip":
		if ip := u.displayIP(); ip != "" {
			if err := setClipboardText(ip); err != nil {
				u.addLog(tr("复制失败")+": "+err.Error(), true)
			} else {
				u.addLog(tr("已复制到剪贴板"), false)
			}
			u.invalidate()
		}
	case id == "outer:wg" || id == "outer:awg":
		p := strings.TrimPrefix(id, "outer:")
		if m.outerProto != p && !m.working && !m.connecting {
			m.outerProto = p
			u.invalidate()
			if m.connected && m.proto == protoWWarp {
				u.doSwitch()
			}
		}
	case id == "inner:wg" || id == "inner:awg":
		p := strings.TrimPrefix(id, "inner:")
		if m.innerProto != p && !m.working && !m.connecting {
			m.innerProto = p
			u.invalidate()
			if m.connected && m.proto == protoWWarp {
				u.doSwitch()
			}
		}
	case id == "pin:clear":
		m.pin = ""
		u.mutateSettings(func(s *clientSettings) { s.Pin = "" })
		u.invalidate()
	case strings.HasPrefix(id, "row:"):
		m.pin = strings.TrimPrefix(id, "row:")
		u.mutateSettings(func(s *clientSettings) { s.Pin = m.pin })
		u.invalidate()
	case id == "core":
		u.doCore()
	case id == "rescannow":
		// In subscription mode the refresh button belongs to the node list on
		// screen: re-download the subscriptions. Sweeping WARP endpoints there
		// refreshed a pool the mode never uses.
		if u.m.set.ConnMode == "subscription" {
			u.refreshSubscriptions()
			return
		}
		u.reloadEndpoints(true)
	case id == "logclear":
		u.m.logs = nil
		u.m.logScroll = 0
		u.invalidate()
	case id == "proxyretry":
		go u.retryProxySet()
	case id == "logcopy":
		if len(u.m.logs) == 0 {
			return
		}
		if err := setClipboardText(u.logText()); err != nil {
			u.addLog(tr("复制失败")+": "+err.Error(), true)
		} else {
			u.addLog(trf("%d 行日志已复制到剪贴板", len(u.m.logs)), false)
		}
		u.invalidate()
	default:
		// Page switcher, settings, about and update: all defined in
		// gui_pages_windows.go, keyed by their id prefix.
		u.actionPages(id)
	}
}

func (u *natUI) doConnect() {
	m := u.m
	if m.connecting || m.working {
		return
	}
	// The stop list is the one thing that outranks the button: a stopped code
	// explains itself instead of starting a pipeline that would fail anyway.
	if m.control.Stopped {
		u.addLog(tr("远程控制：客户端已停用，无法连接"), true)
		u.controlStoppedDialog()
		return
	}
	m.connecting = true
	m.working = true
	m.cancelling = false
	u.connectAsync()
}

// connectAsync runs the connect pipeline in the background; the caller has
// already set the busy flags (doConnect for a plain connect, doSwitch after
// its disconnect phase finished on the GUI thread).
func (u *natUI) connectAsync() {
	m := u.m
	u.stateEpoch.Add(1)
	m.connectAt = time.Now()
	// The pipeline gets its own context so the button can cancel one attempt
	// without touching the window's lifetime.
	ctx, cancel := context.WithCancel(u.ctx)
	u.connectCancel = cancel
	u.persistSession()
	o := defaultConnectOptions(m.proto, m.set.CaptureMode == captureTun, m.set.Rescan)
	// Settings-page knobs ride on top of the session choices: ports, DNS,
	// IPv6, MTU, system proxy and split tunnelling.
	m.set.apply(&o)
	// Only an endpoint the user explicitly pinned becomes -pick. Falling back
	// to the best endpoint here would pin the connect to that single
	// candidate: no rotation to the next cached endpoint, no fresh-scan retry
	// - one half-dead endpoint then fails the whole connect (and every
	// protocol's best going half-dead looks like "nothing connects").
	o.pick = m.pin
	// Psiphon / OpenVPN are orthogonal exit switches, never protocols, and are
	// mutually exclusive: V2 wins when both somehow arrive set. In WARP mode
	// they need a plain WG/AWG/MASQUE underlay; in subscription mode the
	// imported node is the underlay, so the leftover proto must not veto them.
	switch {
	case m.openvpn && u.exitOK():
		o.openvpnMode = true
		o.openvpnRegion = m.set.OpenVPNRegion
		o.openvpnNodePin = m.set.OpenVPNNode
	case m.psiphon && u.exitOK():
		o.psiphonMode = true
	}
	if m.proto == protoWWarp {
		// WARP-in-WARP: runConnectCmd normalises this into the engine's chain
		// form (outer carrier + inner tunnel + auto-picked outer endpoint);
		// the GUI only contributes the two protocol choices.
		o.outerProto = m.outerProto
		o.innerProto = m.innerProto
	}
	proto := m.proto
	// Tee the mihomo core's stdout into the log panel: the pipe is drained by a
	// scanner that feeds each line back to the GUI thread, and closes by itself
	// once the core dies (EOF) or the window does (ctx).
	pr, pw := io.Pipe()
	o.coreLog = pw
	// A busy session makes the core emit thousands of lines a minute. Posting
	// one u.sync per line blocked the reader on the UI thread and buried the
	// repaint queue — the "after a while the window stops responding" report.
	// Lines are queued instead and flushed in batches; a full queue DROPS rather
	// than blocks, because blocking here would back up into the core's stdout
	// and stall the tunnel itself.
	type coreLine struct {
		lv  int
		msg string
	}
	lines := make(chan coreLine, 1024)
	dropped := 0
	go func() {
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		batch := make([]coreLine, 0, 64)
		flush := func() {
			if len(batch) == 0 {
				return
			}
			out := batch
			batch = make([]coreLine, 0, 64)
			u.sync(func() {
				for _, l := range out {
					u.addLogFull(l.msg, l.lv, true)
				}
				u.invalidate()
			})
		}
		for {
			select {
			case <-u.ctx.Done():
				return
			case l, ok := <-lines:
				if !ok {
					flush()
					return
				}
				batch = append(batch, l)
				if len(batch) >= 64 {
					flush()
				}
			case <-t.C:
				flush()
			}
		}
	}()
	go func() {
		sc := bufio.NewScanner(pr)
		// Closing the read end unblocks the exec copier once the scanner exits
		// (window closed), so the pipe can never wedge the child's stdout.
		defer pr.Close()
		defer close(lines)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			select {
			case <-u.ctx.Done():
				return
			default:
			}
			lv, msg := parseCoreLine(line)
			select {
			case lines <- coreLine{lv: lv, msg: msg}:
			default:
				dropped++
				if dropped == 1 || dropped%2000 == 0 {
					n := dropped
					u.sync(func() {
						u.addLog(trf("核心日志过多，已丢弃 %d 行（连接不受影响）", n), false)
					})
				}
			}
		}
	}()
	go func() {
		connectStage = u.connectStageHook
		defer func() { connectStage = nil }()
		err := runConnectCmd(ctx, o)
		_ = pw.Close()
		cancel()
		u.sync(func() {
			u.connectCancel = nil
			u.stateEpoch.Add(1)
			u.m.connecting = false
			u.m.working = false
			u.m.cancelling = false
			u.m.connectAt = time.Time{}
			// Reflect the outcome immediately: leaving connected untouched here
			// let the button flash "connect" between the spinner stopping and
			// the status loop's next 2s poll picking up the new state.
			u.m.connected = err == nil
			// Refresh the status from disk too: the cached one predates this
			// connect, and its stale proxy_warn flashed the blocked banner for
			// a second even when this connect set the proxy fine.
			if st, lerr := loadState(); lerr == nil {
				u.m.status = st
			}
			if err != nil {
				if errors.Is(err, context.Canceled) {
					u.m.connected = false
					u.m.spin = 0
					u.addLog(tr("已取消连接"), false)
					u.invalidate()
					// The attempt may have started a core before it noticed the
					// cancellation: reap it and put the host proxy back, or the
					// next connect finds the mixed port taken.
					go func() {
						if dir, derr := coreDir(); derr == nil {
							core.KillStaleCores(core.CoreInDir(dir))
						}
						_ = runDisconnectCmd(context.Background(), options{mixedPort: core.DefaultMixedPort})
					}()
					return
				}
				u.addLog(err.Error(), true)
			} else {
				u.addLog("已连接", false)
				// A new session starts with a clean slate: any "proxy lost" note
				// from a previous run describes a session that no longer exists.
				u.m.proxyLost = false
				clearProxyLost()
				// No automatic pool refresh after connecting: the user decides
				// when to refresh via the button in the region picker.
				if u.m.openvpn {
					u.loadVPNGateCacheOnly()
				}
			}
			u.applyEndpoints(proto)
			u.invalidate()
		})
	}()
	u.invalidate()
}

func (u *natUI) connectStageHook(s string) {
	u.sync(func() {
		u.addLogStage(s)
		u.invalidate()
	})
}

// cancelConnect aborts an attempt that is still in flight. The pipeline notices
// its context and returns; the disconnect cleanup runs alongside it so a core
// that was already started does not outlive the cancelled attempt.
func (u *natUI) cancelConnect() {
	cancel := u.connectCancel
	if cancel == nil {
		return
	}
	u.connectCancel = nil
	cancel()
	u.m.cancelling = true
	u.addLog(tr("正在取消连接…"), false)
	u.invalidate()
	// Nothing else happens here on purpose. The pipeline returns at its next
	// checkpoint and connectAsync's completion owns the cleanup; running the
	// disconnect in parallel raced it — the pipeline could start its core right
	// after the cleanup finished, and the attempt then reported success minutes
	// after the user had cancelled.
}

func (u *natUI) doDisconnect() {
	// Not connecting: the button shows a busy "断开中" while working, so the
	// connect animation/label must not appear for a disconnect.
	u.stateEpoch.Add(1)
	u.m.working = true
	go func() {
		err := runDisconnectCmd(u.ctx, options{mixedPort: core.DefaultMixedPort})
		u.sync(func() {
			u.stateEpoch.Add(1)
			u.m.connecting = false
			u.m.working = false
			u.m.connected = false
			// The session this note described is over; leaving it behind would
			// make the next launch read a stale warning.
			u.m.proxyLost = false
			clearProxyLost()
			if err != nil {
				u.addLog(err.Error(), true)
			} else {
				u.addLog("已断开", false)
			}
			// Refresh from disk so the tiles/banner reflect the disconnect
			// immediately instead of on the next 2s poll.
			if st, lerr := loadState(); lerr == nil {
				u.m.status = st
			}
			u.invalidate()
		})
	}()
	u.invalidate()
}

// doSwitch swaps protocols on a live connection: disconnect, then reconnect
// with the new selection. The working flag keeps the button busy for the
// whole sequence; the elevated proxy daemon (when needed) makes both the
// restore and the re-set silent — no second UAC prompt.
func (u *natUI) doSwitch() {
	m := u.m
	if m.working || m.connecting {
		return
	}
	m.connecting = true
	m.working = true
	u.addLog("切换协议：断开当前连接并重连…", false)
	go func() {
		_ = runDisconnectCmd(u.ctx, options{mixedPort: core.DefaultMixedPort})
		u.sync(func() { u.connectAsync() })
	}()
	u.invalidate()
}

func (u *natUI) doCore() {
	if u.m.coreBusy {
		return
	}
	dir, err := coreDir()
	if err != nil {
		u.addLog(err.Error(), true)
		return
	}
	u.m.coreBusy = true
	u.addLog("下载/检查 Clash 核心…", false)
	go func() {
		_, err := core.EnsureBinary(dir, "")
		u.sync(func() {
			u.m.coreBusy = false
			if err != nil {
				u.addLog("核心失败: "+err.Error(), true)
			} else {
				u.addLog("核心已就绪", false)
			}
			u.refreshCoreCard(dir)
			u.invalidate()
		})
		if err == nil {
			// The binary may have been replaced at the same path: drop the
			// cached probe result and re-ask the new core what it supports.
			resetCoreCapabilityCache()
			go u.probeCore()
		}
	}()
	u.invalidate()
}

func (u *natUI) refreshCoreCard(dir string) {
	u.m.coreInstalled = false
	u.m.coreSize = 0
	if fi, err := os.Stat(core.CoreInDir(dir)); err == nil && !fi.IsDir() {
		u.m.coreInstalled = true
		u.m.coreSize = fi.Size()
	}
}

// ---------------------------------------------------------------------------
// Hit-testing input
// ---------------------------------------------------------------------------

func (u *natUI) hit(x, y int) (spot, bool) {
	for i := len(u.sp) - 1; i >= 0; i-- {
		s := u.sp[i]
		if x >= s.r.X && x < s.r.X+s.r.Width && y >= s.r.Y && y < s.r.Y+s.r.Height {
			return s, true
		}
	}
	return spot{}, false
}

func (u *natUI) onDown(x, y int) {
	u.clickDebug(x, y)
	// The caption band belongs to the window, not to a page: the three buttons
	// act immediately, and empty space there moves the window.
	if u.inCaption(x, y) {
		if s, ok := u.hit(x, y); ok && s.enabled && strings.HasPrefix(s.id, "cap:") {
			if u.windowAction(s.id) {
				return
			}
		}
		u.startWindowDrag()
		return
	}
	// An open dropdown swallows the click: selecting one of its items lands on
	// the item's own spot, the header spot toggles it closed, and anywhere
	// else just dismisses the popup without activating what is underneath.
	if u.m.dropOpen != "" {
		if s, ok := u.hit(x, y); ok && s.enabled && u.dropSpotOpen(s.id) {
			u.action(s.id)
			return
		}
		u.m.dropOpen = ""
		u.invalidate()
		return
	}
	if s, ok := u.hit(x, y); ok && s.enabled {
		if s.id == "set:scrollbar" {
			u.beginScrollDrag(y)
			return
		}
		if s.id == "log:scrollbar" {
			u.beginLogDrag(y)
			return
		}
		u.action(s.id)
	}
}

// clickDebug appends every press and its hit to %TEMP%\xh-click-debug.log when
// WARP_UI_DEBUG is set — a temporary aid for the visual harness.
func (u *natUI) clickDebug(x, y int) {
	if os.Getenv("WARP_UI_DEBUG") == "" {
		return
	}
	s, ok := u.hit(x, y)
	id := "<none>"
	if ok {
		id = s.id
	}
	u.debugLogf(fmt.Sprintf("down %d,%d -> %s (k=%.3f dw=%.1f dh=%.1f spots=%d)", x, y, id, u.k, u.dw, u.dh, len(u.sp)))
	// Dump the toolbar/manager regions so a harness click that lands on
	// "<none>" can be matched against the rect the painter actually published.
	for _, sp := range u.sp {
		if strings.HasPrefix(sp.id, "drop:") || strings.HasPrefix(sp.id, "sub") ||
			strings.HasPrefix(sp.id, "rescan") || strings.HasPrefix(sp.id, "nodesearch") {
			u.debugLogf(fmt.Sprintf("  %s rect=(%d,%d %dx%d)", sp.id, sp.r.X, sp.r.Y, sp.r.Width, sp.r.Height))
		}
	}
}

// debugLogf appends one line to the harness debug log (env-gated).
func (u *natUI) debugLogf(line string) {
	if os.Getenv("WARP_UI_DEBUG") == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "xh-click-debug.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		_, _ = f.WriteString(time.Now().Format("15:04:05.000") + " " + line + "\r\n")
		_ = f.Close()
	}
}

// dropSpotOpen says whether a spot belongs to the currently open dropdown (its
// header or one of its items), so a click on it is handled rather than
// dismissing the popup.
func (u *natUI) dropSpotOpen(id string) bool {
	switch u.m.dropOpen {
	case "region":
		return id == "drop:region" || strings.HasPrefix(id, "pickregion:")
	case "vpnregion":
		return id == "drop:vpnregion" || strings.HasPrefix(id, "pickvpnregion:") ||
			strings.HasPrefix(id, "vpncountry:") || strings.HasPrefix(id, "pickvpnnode:") ||
			id == "vpnrefresh" || id == "vpnprobe"
	case "proto":
		return id == "drop:proto" || strings.HasPrefix(id, "proto:")
	case "homenode":
		return id == "drop:homenode" || strings.HasPrefix(id, "subpick:") ||
			id == "subauto" || id == "subnodes"
	case "family":
		return id == "drop:family" || strings.HasPrefix(id, "pickfamily:")
	case "preset":
		return id == "drop:preset" || strings.HasPrefix(id, "pickpreset:")
	case "capture":
		return id == "drop:capture" || strings.HasPrefix(id, "pickcapture:")
	case "connmode":
		return id == "drop:connmode" || strings.HasPrefix(id, "connmode:")
	case "addmenu":
		return id == "drop:addmenu" || id == "suburl" || id == "subsingle" ||
			id == "subclip" || id == "subfile" || id == "subqr" || id == "subrefresh"
	case "submgr":
		return id == "drop:submgr" || id == "submgr:import" ||
			strings.HasPrefix(id, "subswitch:") ||
			strings.HasPrefix(id, "subedit:") ||
			strings.HasPrefix(id, "subdel:")
	}
	return false
}

func (u *natUI) onMove(x, y int, b walk.MouseButton) {
	// Dragging a scrollbar owns the pointer until the button is released: walk
	// reports the held button on every move, so no MouseUp hook is needed.
	if u.logDrag {
		if b == 0 {
			u.logDrag = false
		} else {
			u.dragLogTo(y)
			return
		}
	}
	if u.scrollDrag {
		if b == 0 {
			u.scrollDrag = false
		} else {
			u.dragScrollTo(y)
			return
		}
	}
	if s, ok := u.hit(x, y); ok {
		if u.m.hover != s.id {
			u.m.hover = s.id
			u.invalidate()
		}
		return
	}
	if u.m.hover != "" {
		u.m.hover = ""
		u.invalidate()
	}
}

// onWheel scrolls the active page: the settings column, or the node list. The
// row count is whatever the last paint managed to fit, so the wheel can never
// scroll past the end; it only acts below the header band.
func (u *natUI) onWheel(x, y int, b walk.MouseButton) {
	delta := walk.MouseWheelEventDelta(b)
	if delta == 0 || y < u.sy(shellBodyY) {
		return
	}
	// An open VPN Gate country popup scrolls its own list: the pool can expose
	// dozens of countries, more than fit between the field and the frame.
	if u.m.dropOpen == "vpnregion" {
		max := len(u.vpnPopupRows()) - vpnRegionPopupRows
		if max < 0 {
			max = 0
		}
		u.m.vpnScroll -= delta / 40
		if u.m.vpnScroll < 0 {
			u.m.vpnScroll = 0
		}
		if u.m.vpnScroll > max {
			u.m.vpnScroll = max
		}
		u.invalidate()
		return
	}
	// The Psiphon region popup scrolls its own list: the live egress set can
	// expose far more countries than fit between the field and the frame.
	if u.m.dropOpen == "region" {
		max := 1 + len(currentPsiphonRegions()) - regionPopupRows
		if max < 0 {
			max = 0
		}
		u.m.regionScroll -= delta / 40
		if u.m.regionScroll < 0 {
			u.m.regionScroll = 0
		}
		if u.m.regionScroll > max {
			u.m.regionScroll = max
		}
		u.invalidate()
		return
	}
	// The home node dropdown scrolls its own latency-sorted list when it is
	// taller than the rows that fit between the pill and the frame.
	if u.m.dropOpen == "homenode" {
		max := len(u.homeNodeRows()) - u.homeNodeVisible()
		if max < 0 {
			max = 0
		}
		u.m.homeNodeScroll -= delta / 40
		if u.m.homeNodeScroll < 0 {
			u.m.homeNodeScroll = 0
		}
		if u.m.homeNodeScroll > max {
			u.m.homeNodeScroll = max
		}
		u.invalidate()
		return
	}
	// The subscription manager scrolls its own source list when there are more
	// sources than the fixed-height popup can show.
	if u.m.dropOpen == "submgr" {
		max := len(u.m.set.SubSources) - subMgrMaxRows
		if max < 0 {
			max = 0
		}
		u.m.subMgrScroll -= delta / 40
		if u.m.subMgrScroll < 0 {
			u.m.subMgrScroll = 0
		}
		if u.m.subMgrScroll > max {
			u.m.subMgrScroll = max
		}
		u.invalidate()
		return
	}
	if u.m.page == pageLogs && u.m.logTab == "run" {
		rows := u.m.logVisibleRows
		if rows < 1 {
			rows = 1
		}
		max := len(u.m.logs) - rows
		if max < 0 {
			max = 0
		}
		// logScroll counts UP from the newest line (0 = follow the live bottom),
		// the opposite of the top-down offsets the other pages use, so the wheel
		// sign is flipped here: wheel down heads toward the newest, wheel up
		// toward older history.
		u.m.logScroll += delta / 40
		if u.m.logScroll < 0 {
			u.m.logScroll = 0
		}
		if u.m.logScroll > max {
			u.m.logScroll = max
		}
		u.invalidate()
		return
	}
	if u.m.page == pageSettings {
		u.m.setScroll -= delta / 2
		u.clampSetScroll()
		u.invalidate()
		return
	}
	if u.m.page != pageNodes || y < u.sy(shellBodyY) {
		return
	}
	// Both modes now render one row table; paintModeTable publishes the visible
	// row count and the largest scroll offset for whichever mode is active.
	if u.m.subVisibleRows == 0 {
		return
	}
	u.m.scroll -= delta / 40
	if u.m.scroll < 0 {
		u.m.scroll = 0
	}
	if u.m.scroll > u.m.subMaxScroll {
		u.m.scroll = u.m.subMaxScroll
	}
	u.invalidate()
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------

// paintPanics counts recovered paint panics: a broken frame must not flood the
// log at sixteen repaints a second.
var paintPanics int

func (u *natUI) paint(c *walk.Canvas, _ walk.Rectangle) (err error) {
	// Hit regions are rebuilt every frame. Publishing a half-built map was
	// fatal: the old code cleared u.sp first, so any panic or early return left
	// a black window with ZERO clickable spots — "全黑后怎么点都没反应" was
	// permanent. Build into a scratch slice and publish only a complete frame.
	prevSpots := u.sp
	u.sp = make([]spot, 0, len(prevSpots))
	frameOK := false
	defer func() {
		if rec := recover(); rec != nil {
			paintPanics++
			if paintPanics <= 3 {
				u.appendLog(fmt.Sprintf("界面绘制异常（已跳过该帧）: %v", rec), 2, false, false)
			}
			err = nil
		}
		if !frameOK {
			u.sp = prevSpots
			// Ask for one more frame, but never spin forever on a permanent bug.
			if paintPanics <= 12 {
				u.sync(func() { u.invalidate() })
			}
		}
	}()
	b := u.mw.ClientBoundsPixels()
	pxW := b.Width
	if pxW < 10 {
		pxW = 1080
	}
	// The design grid is 1080 wide and (700 + caption) tall; the display scales
	// it, and every widget converts through u.r/u.s.
	pxH := b.Height
	if pxH < 10 {
		pxH = 700 + capH
	}
	// Adaptive engine: k is the display DPI alone, so a logical pixel is a
	// physical pixel at 100% and twice that at 200%. dw/dh are the logical
	// client size the breakpoints lay out against; nothing letterboxes.
	dpi := c.DPI()
	if dpi <= 0 {
		dpi = 96
	}
	u.k = float64(dpi) / 96.0
	u.ox = 0
	u.oy = 0
	// The page-transition offset is transient: clear it before the wallpaper and
	// sidebar paint so only paintShell's page body ever moves.
	u.ax, u.ay = 0, 0
	u.winW = float64(pxW) / u.k
	u.dw = u.winW
	u.dh = float64(pxH)/u.k - capH
	// Every page is authored on a fixed 700-tall grid. When the window is
	// shorter than that, shrink the whole page to fit instead of clipping.
	// The factor stays in u.k after paint, so hit-testing matches the frame the
	// user sees. Home shares the same factor: its sidebar, type and content
	// must stay the same size as the other pages at the same window size.
	if u.dh < 700 {
		u.k *= u.dh / 700
		u.dw = float64(pxW) / u.k
		u.dh = float64(pxH)/u.k - capH
	}
	// Type follows the window, not the display: k already carries the DPI, so
	// dividing it out leaves the pure zoom the font ramp must follow.
	u.scaleFonts(u.k * 96.0 / float64(dpi))

	// One background brush per frame, always disposed. The old code passed
	// u.brush() straight into FillRectanglePixels: that handle was never freed
	// (measured leak ≈ 3.3 GDI objects/second), and any failure returned early
	// BEFORE wallpaper/shell were drawn. On Windows 11 26H2 a transient GDI or
	// DPI condition therefore produced a permanently black, unclickable window.
	// Use the sanitised size too: a 0x0 client bounds rectangle can be valid
	// during a DPI/resize transition and must not abort the whole frame.
	if bg := u.brush(th.window); bg != nil {
		if ferr := c.FillRectanglePixels(bg, walk.Rectangle{X: 0, Y: 0, Width: pxW, Height: pxH}); ferr != nil && paintPanics == 0 {
			u.appendLog("背景绘制失败（已继续绘制界面）: "+ferr.Error(), 2, false, false)
		}
		bg.Dispose()
	}
	u.paintWallpaper(c, pxW, pxH)
	u.paintShell(c)
	frameOK = true
	return nil
}

func (u *natUI) measure(c *walk.Canvas, s string, f *walk.Font) int {
	// TextCalcRect (DT_CALCRECT) is required: walk's MeasureTextPixels draws into
	// a metafile without it, so DrawTextEx leaves the rect at the proposed width
	// (10000) instead of shrinking it to the text. Without the flag every
	// measured width came back 10000, throwing centred brand text off-screen.
	b, _, _ := c.MeasureTextPixels(s, f, walk.Rectangle{X: 0, Y: 0, Width: 10000, Height: 200}, walk.TextSingleLine|walk.TextNoPrefix|walk.TextCalcRect)
	return b.Width
}

// speedText formats a bytes/sec rate for the traffic card.
func speedText(bps int64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", float64(bps)/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.1f KB/s", float64(bps)/(1<<10))
	default:
		return fmt.Sprintf("%d B/s", bps)
	}
}

// fetchLocalProbe asks a geo endpoint directly (no tunnel) for the machine's
// public IP and where it sits, so the home tiles have a country to show before
// the first connect. Sources in order: Cloudflare meta, then ip-api (its plain
// HTTP endpoint answers where CF's TLS one is unreachable). Each source is
// tried direct AND through the WinINET system proxy, because on exactly the
// networks this client exists for direct egress is what is broken — while the
// user's other tooling already talks through a local proxy.
func fetchLocalProbe() (ip, cc, city string, err error) {
	var lastErr error
	for _, url := range []string{
		"https://speed.cloudflare.com/meta",
		"http://ip-api.com/json/?fields=query,countryCode,country,city&lang=zh-CN",
	} {
		for _, client := range localProbeClients() {
			var r struct {
				// cloudflare meta
				ClientIP string `json:"clientIp"`
				Country  string `json:"country"`
				City     string `json:"city"`
				Colo     struct {
					City string `json:"city"`
				} `json:"colo"`
				// ip-api
				Query       string `json:"query"`
				CountryCode string `json:"countryCode"`
			}
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				lastErr = err
				continue
			}
			// Same as fetchMeta: /meta answers 403 (or {}) without a Referer,
			// so the CF source in this idle probe was always dead and the tile
			// only ever got its country from the ip-api fallback.
			if strings.HasPrefix(url, "https://speed.cloudflare.com") {
				req.Header.Set("Referer", metaReferer)
			}
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				continue
			}
			body := make([]byte, 8192)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				lastErr = fmt.Errorf("local probe: HTTP %d", resp.StatusCode)
				continue
			}
			if err := json.Unmarshal(body[:n], &r); err != nil {
				lastErr = err
				continue
			}
			ip, cc := r.ClientIP, r.Country
			if ip == "" {
				ip, cc = r.Query, r.CountryCode
			}
			if r.City == "" {
				r.City = r.Colo.City
			}
			if ip == "" {
				lastErr = fmt.Errorf("local probe: no ip in reply")
				continue
			}
			return strings.TrimSpace(ip), cc, r.City, nil
		}
	}
	return "", "", "", lastErr
}

// localProbeClients is the transport set for the idle-state geo probe: direct
// (with env-proxy support) plus the WinINET system proxy when one is enabled.
// Probe transports are cached per proxy URL. Building a fresh http.Transport on
// every poll leaked one connection pool every 2 seconds: the old transport's
// idle connections and its reader goroutines are never collected, which showed
// up as ~45 handles and ~2.5MB per minute of working set while connected —
// the "memory keeps climbing" report. A cached client also reuses the TCP+TLS
// connection, so the probe itself gets cheaper.
var (
	probeClientMu sync.Mutex
	probeClients  = map[string]*http.Client{}
)

func probeClientFor(proxyURL string) *http.Client {
	probeClientMu.Lock()
	defer probeClientMu.Unlock()
	if c, ok := probeClients[proxyURL]; ok {
		return c
	}
	t := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyURL != "" {
		if pu, err := url.Parse(proxyURL); err == nil {
			t.Proxy = http.ProxyURL(pu)
		}
	}
	c := &http.Client{Timeout: 6 * time.Second, Transport: t}
	probeClients[proxyURL] = c
	return c
}

func localProbeClients() []*http.Client {
	clients := []*http.Client{probeClientFor("")}
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		en, _, _ := k.GetIntegerValue("ProxyEnable")
		srv, _, _ := k.GetStringValue("ProxyServer")
		if en == 1 && srv != "" {
			if !strings.Contains(srv, "://") {
				srv = "http://" + srv
			}
			clients = append(clients, probeClientFor(srv))
		}
	}
	return clients
}

// directLatency times a plain TCP handshake: the idle-state stand-in for the
// tunnel delay the status loop measures through mihomo. AliDNS first (it
// answers where international anycast is filtered), then 1.1.1.1.
func directLatency() int64 {
	for _, addr := range []string{"223.5.5.5:443", "1.1.1.1:443"} {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return time.Since(start).Milliseconds()
	}
	return 0
}

// localLanIP returns the machine's LAN address (UDP connect does not send a
// packet, it just resolves the outbound route).
// virtualAdapterMarkers are name fragments of adapters that exist only inside
// this machine: Docker/WSL/Hyper-V vEthernet, VMware, VirtualBox, VPN taps. A
// phone on the same Wi-Fi cannot route to any of them, so picking one makes
// "LAN sharing" look broken while the port really is listening on 0.0.0.0.
var virtualAdapterMarkers = []string{
	"vethernet", "virtual", "vmware", "virtualbox", "hyper-v", "docker",
	"wsl", "loopback", "tap-", "tun", "tailscale", "zerotier", "wireguard",
	"clash", "mihomo", "npcap", "vpn", "teredo", "isatap", "6to4",
}

func isVirtualAdapterName(name string) bool {
	low := strings.ToLower(name)
	for _, m := range virtualAdapterMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// lanScore ranks an IPv4 address as "what another device on this network should
// dial". 192.168/16 is the home-router default and wins; 10/8 is the corporate
// equivalent; 172.16/12 is deliberately last because Docker and WSL both live
// there and a stale container network otherwise wins over the real adapter.
func lanScore(ip net.IP) int {
	ip4 := ip.To4()
	if ip4 == nil {
		return -1
	}
	switch {
	case ip4[0] == 192 && ip4[1] == 168:
		return 100
	case ip4[0] == 10:
		return 90
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return 10
	case ip4[0] == 169 && ip4[1] == 254:
		return -1 // APIPA: no DHCP lease, useless
	default:
		return 50
	}
}

// localLanIP returns the address other devices on the same network should use.
//
// The UDP-dial trick alone is not enough: with Docker, WSL or Hyper-V installed
// the kernel may answer with a vEthernet address (172.17.x.x) that no phone can
// reach. That is exactly how "the port is listening but the phone cannot
// connect" happens, and it also put a 172.x address on the home page where the
// user expects their real 192.168.x one.
func localLanIP() string {
	best, bestScore := "", -1
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			if isVirtualAdapterName(ifi.Name) {
				continue
			}
			addrs, aerr := ifi.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
					continue
				}
				if s := lanScore(ipn.IP); s > bestScore {
					best, bestScore = ipn.IP.To4().String(), s
				}
			}
		}
	}
	if best != "" {
		return best
	}
	// No physical adapter answered: fall back to whatever route the kernel
	// would take, so a machine with only a virtual adapter still shows
	// something rather than an empty tile.
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// displayIP is what the home IP tile shows: the tunnel's exit once connected,
// the machine's own LAN address before that. While connected an empty exit IP
// must stay empty rather than fall back to the LAN address - showing the
// machine's own IP on a live tunnel is worse than showing a pending dash.
func (u *natUI) displayIP() string {
	if u.m.connected {
		return strings.TrimSpace(u.m.status.ExitIP)
	}
	if u.m.localLan != "" {
		return u.m.localLan
	}
	return u.m.localIP
}

// osRegionCC is the two-letter country of the Windows region setting, used as
// the flag's fallback while idle: the public-IP probe needs a round trip, and a
// card that shows a globe and a dash for the first seconds of every launch
// looks broken next to one that already knows the machine is in CN.
var (
	regionOnce sync.Once
	regionCC   string
)

// displayGeo is the country/city pair under the IP: exit geo when connected,
// the machine's public-IP geo while idle. An OpenVPN session prefers the relay
// node's own country over the stored one: the node is what the user picked and
// what the exit IP belongs to, while the stored geo can still name the WARP
// carrier until the next probe corrects it.
func (u *natUI) displayGeo() (cc, city string) {
	if u.m.connected {
		if u.m.status.OpenVPNMode && u.m.status.OpenVPNNode != nil {
			if ncc := strings.ToUpper(strings.TrimSpace(u.m.status.OpenVPNNode.CountryShort)); ncc != "" {
				return ncc, u.m.status.NodeCity
			}
		}
		return u.m.status.Country, u.m.status.NodeCity
	}
	return u.m.localCC, u.m.localCity
}

// drawFlag paints a small flag chip for an ISO alpha-2 code with plain canvas
// fills: stripes and a glyph approximate every flag traffic can realistically
// exit through; unknown codes get a neutral chip with the code itself.
func (u *natUI) drawFlag(c *walk.Canvas, x, y, w, h float64, cc string) {
	if cc == "" {
		return
	}
	white := rx(255, 255, 255)
	stripes := func(cols ...walk.Color) { // horizontal bands
		sh := h / float64(len(cols))
		for i, col := range cols {
			u.fillRect(c, col, u.r(x, y+float64(i)*sh, w, sh+0.5))
		}
	}
	vstripes := func(cols ...walk.Color) { // vertical bands
		sw := w / float64(len(cols))
		for i, col := range cols {
			u.fillRect(c, col, u.r(x+float64(i)*sw, y, sw+0.5, h))
		}
	}
	disc := func(col walk.Color, dx, dy, dw, dh float64) {
		b := u.brush(col)
		_ = c.FillEllipsePixels(b, u.r(x+dx*w, y+dy*h, dw*w, dh*h))
		b.Dispose()
	}
	star := func(col walk.Color, fx float64) {
		u.textC(c, "★", u.f.f8, col, u.r(x+fx*w, y+2, w*0.45, h-4))
	}
	// starAt draws a five-pointed star as a body disc plus five thick rays.
	// A ★ glyph at this size is a smudge, and GDI+ here has no polygon fill, so
	// this is the smallest shape that still reads as "star" on a 40px flag —
	// which is what the PRC flag needs five of, not one.
	starAt := func(col walk.Color, cx, cy, r float64) {
		u.circleFill(c, col, cx, cy, r*0.40)
		for i := 0; i < 5; i++ {
			ang := -math.Pi/2 + float64(i)*2*math.Pi/5
			cs, sn := math.Cos(ang), math.Sin(ang)
			u.thickLine(c, col, cx+cs*r*0.30, cy+sn*r*0.30, cx+cs*r, cy+sn*r, r*0.45)
		}
	}
	switch cc {
	case "CN":
		// 五星红旗: one large star and four small ones on the arc that points at
		// it, in the flag's own 30x20 unit grid.
		u.fillRect(c, rx(238, 28, 37), u.r(x, y, w, h))
		u64 := w / 30
		yellow := rx(255, 222, 0)
		starAt(yellow, x+5*u64, y+5*u64, 3*u64)
		for _, p := range [][2]float64{{10, 2}, {12, 4}, {12, 7}, {10, 9}} {
			starAt(yellow, x+p[0]*u64, y+p[1]*u64, 1.1*u64)
		}
	case "SG":
		stripes(rx(239, 51, 64), white)
		star(rx(255, 222, 0), 0.05)
	case "US":
		for i := 0; i < 7; i++ {
			col := rx(178, 34, 52)
			if i%2 == 1 {
				col = white
			}
			u.fillRect(c, col, u.r(x, y+float64(i)*h/7, w, h/7+0.5))
		}
		u.fillRect(c, rx(60, 59, 110), u.r(x, y, w*0.42, h*0.55))
	case "JP":
		u.fillRect(c, white, u.r(x, y, w, h))
		disc(rx(188, 0, 45), 0.26, 0.22, 0.44, 0.56)
	case "DE":
		stripes(rx(0, 0, 0), rx(221, 0, 0), rx(255, 206, 0))
	case "FR":
		vstripes(rx(0, 35, 149), white, rx(237, 41, 57))
	case "IT":
		vstripes(rx(0, 146, 70), white, rx(206, 43, 55))
	case "NL":
		stripes(rx(174, 28, 40), white, rx(33, 70, 139))
	case "RU":
		stripes(white, rx(0, 57, 166), rx(213, 43, 30))
	case "GB":
		u.fillRect(c, rx(1, 33, 105), u.r(x, y, w, h))
		u.fillRect(c, white, u.r(x, y+h*0.4, w, h*0.2))
		u.fillRect(c, white, u.r(x+w*0.4, y, w*0.2, h))
		u.fillRect(c, rx(200, 16, 46), u.r(x, y+h*0.44, w, h*0.12))
		u.fillRect(c, rx(200, 16, 46), u.r(x+w*0.44, y, w*0.12, h))
	case "KR":
		u.fillRect(c, white, u.r(x, y, w, h))
		disc(rx(205, 46, 58), 0.25, 0.28, 0.34, 0.34)
		disc(rx(0, 71, 160), 0.25, 0.42, 0.34, 0.34)
	case "HK":
		u.fillRect(c, rx(222, 41, 16), u.r(x, y, w, h))
		star(white, 0.28)
	case "TW":
		u.fillRect(c, rx(254, 0, 0), u.r(x, y, w, h))
		u.fillRect(c, rx(0, 0, 149), u.r(x, y, w*0.5, h*0.5))
		star(white, 0.05)
	case "IN":
		stripes(rx(255, 153, 51), white, rx(19, 136, 8))
		disc(rx(0, 0, 128), 0.35, 0.3, 0.3, 0.4)
	case "BR":
		u.fillRect(c, rx(0, 156, 59), u.r(x, y, w, h))
		disc(rx(255, 223, 0), 0.15, 0.15, 0.7, 0.7)
		disc(rx(0, 39, 118), 0.3, 0.32, 0.4, 0.36)
	case "CA":
		u.fillRect(c, white, u.r(x, y, w, h))
		u.fillRect(c, rx(216, 6, 33), u.r(x, y, w*0.25, h))
		u.fillRect(c, rx(216, 6, 33), u.r(x+w*0.75, y, w*0.25, h))
		star(rx(216, 6, 33), 0.3)
	case "SE":
		u.fillRect(c, rx(0, 106, 167), u.r(x, y, w, h))
		u.fillRect(c, rx(252, 204, 2), u.r(x+w*0.25, y, w*0.14, h))
		u.fillRect(c, rx(252, 204, 2), u.r(x, y+h*0.42, w, h*0.16))
	case "CH":
		u.fillRect(c, rx(218, 41, 28), u.r(x, y, w, h))
		u.fillRect(c, white, u.r(x+w*0.42, y+h*0.15, w*0.16, h*0.7))
		u.fillRect(c, white, u.r(x+w*0.15, y+h*0.42, w*0.7, h*0.16))
	case "ES":
		u.fillRect(c, rx(170, 21, 27), u.r(x, y, w, h*0.25))
		u.fillRect(c, rx(241, 191, 0), u.r(x, y+h*0.25, w, h*0.5))
		u.fillRect(c, rx(170, 21, 27), u.r(x, y+h*0.75, w, h*0.25))
	case "MX":
		vstripes(rx(0, 104, 71), white, rx(206, 17, 38))
	case "VN":
		u.fillRect(c, rx(218, 37, 29), u.r(x, y, w, h))
		star(rx(255, 205, 0), 0.28)
	case "TH":
		u.fillRect(c, rx(165, 25, 49), u.r(x, y, w, h*0.15))
		u.fillRect(c, white, u.r(x, y+h*0.15, w, h*0.15))
		u.fillRect(c, rx(45, 42, 74), u.r(x, y+h*0.3, w, h*0.4))
		u.fillRect(c, white, u.r(x, y+h*0.7, w, h*0.15))
		u.fillRect(c, rx(165, 25, 49), u.r(x, y+h*0.85, w, h*0.15))
	case "AE":
		u.fillRect(c, rx(0, 129, 63), u.r(x, y, w, h))
		u.fillRect(c, white, u.r(x+w*0.25, y+h/3, w*0.75, h/3+0.5))
		u.fillRect(c, rx(0, 0, 0), u.r(x+w*0.25, y+2*h/3, w*0.75, h/3+0.5))
		u.fillRect(c, rx(239, 51, 64), u.r(x, y, w*0.25, h))
	case "TR":
		u.fillRect(c, rx(227, 10, 23), u.r(x, y, w, h))
		disc(white, 0.15, 0.25, 0.3, 0.5)
		disc(rx(227, 10, 23), 0.22, 0.28, 0.3, 0.44)
		star(white, 0.5)
	case "AU", "NZ":
		u.fillRect(c, rx(1, 33, 105), u.r(x, y, w, h))
		u.fillRect(c, white, u.r(x, y+h*0.18, w*0.45, h*0.14))
		u.fillRect(c, white, u.r(x+w*0.16, y, w*0.14, h*0.55))
		u.fillRect(c, rx(200, 16, 46), u.r(x+w*0.19, y, w*0.08, h*0.55))
		u.fillRect(c, rx(200, 16, 46), u.r(x, y+h*0.21, w*0.45, h*0.08))
		if cc == "AU" {
			star(white, 0.55)
		} else {
			star(rx(200, 16, 46), 0.55)
		}
	case "ID":
		u.fillRect(c, rx(206, 17, 38), u.r(x, y, w, h*0.5))
		u.fillRect(c, white, u.r(x, y+h*0.5, w, h*0.5))
	case "MY":
		for i := 0; i < 7; i++ {
			col := rx(255, 0, 0)
			if i%2 == 1 {
				col = white
			}
			u.fillRect(c, col, u.r(x, y+float64(i)*h/7, w, h/7+0.5))
		}
		u.fillRect(c, rx(1, 0, 102), u.r(x, y, w*0.4, h*0.55))
		star(rx(255, 222, 0), 0.02)
	case "PH":
		u.fillRect(c, rx(0, 56, 168), u.r(x, y, w, h*0.5))
		u.fillRect(c, rx(206, 17, 38), u.r(x, y+h*0.5, w, h*0.5))
		disc(white, 0.05, 0.3, 0.35, 0.4)
	default:
		u.fillRound(c, th.chip, u.r(x, y, w, h), 2)
		u.textC(c, cc, u.f.f8, th.dim, u.r(x, y, w, h))
	}
	u.strokeRound(c, th.line, u.r(x, y, w, h), 2)
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// parseCoreLine maps one mihomo logfmt line (time="..." level=... msg="...")
// to a log level and a clean message for the log panel.
func parseCoreLine(line string) (int, string) {
	lv := 0
	switch extractLogfmt(line, "level") {
	case "warning", "warn":
		lv = 1
	case "error", "fatal":
		lv = 2
	}
	if msg := extractLogfmt(line, "msg"); msg != "" {
		return lv, msg
	}
	return lv, line
}

// extractLogfmt pulls the value of key from a logfmt line. Values are quoted
// (msg="...") or bare words (level=info).
func extractLogfmt(line, key string) string {
	i := strings.Index(line, key+"=")
	if i < 0 {
		return ""
	}
	rest := line[i+len(key)+1:]
	if !strings.HasPrefix(rest, `"`) {
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	rest = rest[1:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// coloCountry maps a Cloudflare colo code (metro IATA) to its ISO country,
// so the endpoint list and status tiles can show a flag next to it.
var coloCountry = map[string]string{
	// United States
	"LAX": "US", "SEA": "US", "SJC": "US", "SFO": "US", "DFW": "US",
	"IAD": "US", "EWR": "US", "JFK": "US", "ORD": "US", "MIA": "US",
	"ATL": "US", "BOS": "US", "PHX": "US", "DEN": "US", "LAS": "US",
	"PDX": "US", "MCI": "US", "SLC": "US", "DTW": "US", "MSP": "US",
	"CLT": "US", "BNA": "US", "PIT": "US", "CLE": "US", "IND": "US",
	"CMH": "US", "RDU": "US", "TPA": "US", "AUS": "US", "SAT": "US",
	// Canada
	"YYZ": "CA", "YVR": "CA", "YOW": "CA", "YUL": "CA", "YYC": "CA",
	// Latin America
	"GRU": "BR", "GIG": "BR", "POA": "BR", "CWB": "BR", "BOG": "CO",
	"LIM": "PE", "SCL": "CL", "EZE": "AR", "MEX": "MX", "QRO": "MX",
	"CCS": "VE", "SJO": "CR", "PTY": "PA",
	// Europe
	"LHR": "GB", "MAN": "GB", "EDI": "GB", "AMS": "NL", "FRA": "DE",
	"MUC": "DE", "DUS": "DE", "HAM": "DE", "BER": "DE", "CDG": "FR",
	"MRS": "FR", "LYS": "FR", "MXP": "IT", "FCO": "IT", "MAD": "ES",
	"BCN": "ES", "ARN": "SE", "CPH": "DK", "OSL": "NO", "HEL": "FI",
	"WAW": "PL", "VIE": "AT", "ZRH": "CH", "GVA": "CH", "BRU": "BE",
	"LIS": "PT", "PRG": "CZ", "BUD": "HU", "OTP": "RO", "SOF": "BG",
	"ATH": "GR", "DUB": "IE", "LUX": "LU", "KEF": "IS",
	// Middle East / Africa
	"DXB": "AE", "FJR": "AE", "DOH": "QA", "KWI": "KW", "RUH": "SA",
	"TLV": "IL", "IST": "TR", "JNB": "ZA", "CPT": "ZA", "NBO": "KE",
	"LOS": "NG", "CAI": "EG", "CMN": "MA",
	// Asia-Pacific
	"SIN": "SG", "HKG": "HK", "NRT": "JP", "KIX": "JP", "ICN": "KR",
	"TPE": "TW", "BOM": "IN", "DEL": "IN", "MAA": "IN", "BLR": "IN",
	"BKK": "TH", "SGN": "VN", "HAN": "VN", "MNL": "PH", "CGK": "ID",
	"DPS": "ID", "KUL": "MY", "PEN": "MY", "SYD": "AU", "MEL": "AU",
	"PER": "AU", "BNE": "AU", "AKL": "NZ", "WLG": "NZ",
	// CIS
	"SVO": "RU", "LED": "RU", "ALA": "KZ", "TAS": "UZ", "KBP": "UA",
	"MSQ": "BY",
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func latencyText(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return strconv.FormatInt(ms, 10) + "ms"
}

func sizeText(b int64) string {
	if b >= 1<<20 {
		return strconv.FormatFloat(float64(b)/(1<<20), 'f', 1, 64) + " MB"
	}
	return strconv.FormatInt(b/1024, 10) + " KB"
}
