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
	"unsafe"

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
	fmono                                                                                        *walk.Font
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
	vpnProbeBusy bool // latency probe for the cached pool is in flight
	vpnMeasured  bool // the current pool already carries measured latency

	endpoints []cachedEndpoint
	pin       string
	scanFresh bool
	scanAt    time.Time

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
	logTab          string
	logScroll       int // run-log lines scrolled up from the newest; 0 follows live
	logVisibleRows  int // rows the last run-log paint could show

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

	f  fonts
	sp []spot
	k  float64

	// The design grid is 1080x700 and is scaled uniformly (u.k) into the client
	// area: oy is the vertical letterbox offset in device pixels, and dw is the
	// grid *width* in design units, which grows with a wide window so the cards
	// take the extra space instead of leaving a blank strip on the right.
	ox, oy int
	dw     float64
	// fonts is the ramp's construction table, and fontK the scale it was built
	// for: paint rebuilds the whole ramp when the window scale drifts.
	fonts []fontSpec
	fontK float64

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

	// ni is the tray icon. Closing the window hides it there instead of
	// quitting, so the tunnel keeps running; the close is only allowed once
	// u.quitting is set from the tray menu.
	ni            *walk.NotifyIcon
	quitting      bool
	quitScheduled bool
	trayHinted    bool

	// scrollDrag is the settings scrollbar's grab state: the wheel used to be
	// the only way to scroll that page, which is what users complained about.
	scrollDrag   bool
	scrollGrabDY float64 // pointer offset inside the thumb, design units

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
func (u *natUI) sx(v float64) int { return u.ox + u.s(v) }
func (u *natUI) sy(v float64) int { return u.oy + u.s(v+capH) }

// ux / uy are the inverse, for the few places that reason about a point the
// canvas already drew (the sparkline column fill).
func (u *natUI) ux(px int) float64 { return (float64(px) - float64(u.ox)) / u.k }
func (u *natUI) uy(px int) float64 { return (float64(px) - float64(u.oy)) / u.k }

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
		Width:  int(math.Round(designW * dpi / 96)),
		Height: int(math.Round(designH * dpi / 96)),
	}); err != nil {
		mw.Dispose()
		return fmt.Errorf("set client size: %w", err)
	}
	// The layout is a uniformly scaled 1080x734 grid, so the floor can sit well
	// under the design size: everything shrinks with it instead of clipping. The
	// minimum keeps the design ratio, so a dragged window never letterboxes.
	mw.SetMinMaxSizePixels(walk.Size{Width: 800, Height: 544}, walk.Size{})

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

	// The reference mock uses one weight throughout: nothing is bold. Every
	// face is therefore created with style 0 — the *b token names stay because
	// the paint sites already pick the right role, they just no longer shout.
	// Hierarchy comes from size and colour, exactly as in the mock.
	u.fonts = []fontSpec{
		{&u.f.f8, uiFont, 9, 0},    // caption / hint
		{&u.f.f9, uiFont, 10, 0},   // label, list text
		{&u.f.f10, uiFont, 11, 0},  // body
		{&u.f.f10b, uiFont, 11, 0}, // body (same weight, by design)
		{&u.f.f11b, uiFont, 11, 0}, // card title
		{&u.f.f12b, uiFont, 12, 0}, // stat value, tab
		{&u.f.f12, uiFont, 10, 0},  // small
		{&u.f.f13, uiFont, 11, 0},  // sidebar status
		{&u.f.f13b, uiFont, 12, 0}, // brand, button word
		{&u.f.f15, uiFont, 12, 0},  // placeholder
		{&u.f.f15b, uiFont, 15, 0}, // page title
		{&u.f.f16b, uiFont, 13, 0}, // sidebar item
		{&u.f.f17b, uiFont, 15, 0}, // big value (IP, rate, ms)
		{&u.f.f18b, uiFont, 17, 0}, // display
		{&u.f.f22b, uiFont, 18, 0}, // display, large
		{&u.f.f25b, uiFont, 20, 0}, // hero
		{&u.f.f30b, uiFont, 24, 0}, // hero, large
		{&u.f.fmono, "Consolas", 10, 0},
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
	go u.spinLoop()
	go u.probeCore()         // stats the core, asks it which protocols it can parse
	u.reloadEndpoints(false) // fast cache read on the (main) GUI goroutine
	u.refreshVPNGatePool()   // cached country list for the OpenVPN exit selector

	// Closing the window parks it in the tray instead of quitting: the session
	// keeps running, which is what a VPN client has to do. Only the tray menu's
	// "exit" sets u.quitting and lets the close through.
	mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if u.quitting {
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
	// Hand health ownership back: this window's claim must not outlive it, or
	// every other process would keep standing aside for an owner that left.
	releaseHealthOwner(os.Getpid())
	u.disposeFonts()
	disposeLogo()
	cw.Dispose()
	mw.Dispose()
	return nil
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

func (u *natUI) sync(f func()) {
	if u.cw != nil {
		u.mw.Synchronize(f)
	}
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

func (u *natUI) statusLoop() {
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
			// Persist a relay-country correction once, so status/CLI and the
			// next process agree with what the home page now shows.
			if st.Connected && st.OpenVPNMode && cc != "" && st.Country != cc {
				st.Country, st.Colo, st.NodeCity = cc, colo, city
				_ = saveState(st)
			}
			st.ExitIP, st.Country, st.Colo, st.NodeCity = exIP, cc, colo, city
			u.m.status = st
			u.m.proxyBlocker = blocker
			// While an attempt is in flight the pipeline owns this flag. A poll
			// that read state.json before the cancel landed must not flip the
			// button back to "已连接" afterwards — that is the "cancelled, then
			// suddenly connected" report.
			if !u.m.connecting && !u.m.cancelling && !u.m.working {
				u.m.connected = st.Connected
			}
			if u.m.localLan == "" {
				u.m.localLan = localLanIP()
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
			}
			if !st.Connected && (len(u.m.upRates) > 0 || len(u.m.downRates) > 0) {
				u.m.upRates, u.m.downRates = nil, nil
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
	// 40ms (25fps) is the slowest rate at which a rotating arc still reads as
	// smooth; the previous 60ms tick visibly stepped.
	t := time.NewTicker(40 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		u.sync(func() {
			if u.m.connecting {
				u.m.spin++
				u.invalidate()
			}
		})
	}
}

func (u *natUI) reloadEndpoints(force bool) {
	proto := u.m.proto
	outer, inner := u.m.outerProto, u.m.innerProto
	if force {
		go func() {
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
				u.m.vpnMeasured = true
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

// fetchVPNGatePool runs the whole fetch pipeline off the GUI thread and probes
// latency through whichever route delivered the list. route names the path that
// answered, for the run log.
func (u *natUI) fetchVPNGatePool() ([]vpnGateNode, string, error) {
	directErr := error(nil)
	if raw, err := fetchVPNGateDirect(u.ctx); err == nil {
		if nodes := parseVPNGateCSV(raw); len(nodes) > 0 {
			u.sync(func() { u.m.vpnPoolNote = tr("正在识别家宽/机房节点…") })
			enrichCtx, cancel := context.WithTimeout(u.ctx, 20*time.Second)
			_, _ = enrichVPNGateClasses(enrichCtx, &http.Client{Timeout: 15 * time.Second}, nodes)
			cancel()
			u.sync(func() { u.m.vpnPoolNote = tr("正在测量节点延迟…") })
			measureVPNGateLatency(u.ctx, nodes)
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
				u.sync(func() { u.m.vpnPoolNote = tr("正在识别家宽/机房节点…") })
				enrichCtx, cancel := context.WithTimeout(u.ctx, 20*time.Second)
				_, _ = enrichVPNGateClasses(enrichCtx, vpnGateProxyClient(st.MixedPort, 15*time.Second), nodes)
				cancel()
				u.sync(func() { u.m.vpnPoolNote = tr("正在测量节点延迟…") })
				measureVPNGateLatency(u.ctx, nodes)
				sortVPNGateNodesByLatency(nodes)
				return nodes, "本机代理", nil
			}
		} else {
			proxyErr = perr
		}
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
	if cs, ok := cachedScanFor(underlay, false); ok {
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
	return fetchVPNGateNodesViaWARP(u.ctx, results, run, prefer)
}

// probeVPNGateLatencyAsync fills in the latency column when the pool came from
// the cache: the cache intentionally stores no timing, so without this the
// picker would show "未测" for every node until the next live fetch.
func (u *natUI) probeVPNGateLatencyAsync() {
	if u.m.vpnProbeBusy || u.m.vpnMeasured || len(u.m.vpnNodes) == 0 {
		return
	}
	u.m.vpnProbeBusy = true
	nodes := append([]vpnGateNode(nil), u.m.vpnNodes...)
	go func() {
		measureVPNGateLatency(u.ctx, nodes)
		sortVPNGateNodesByLatency(nodes)
		u.sync(func() {
			u.m.vpnProbeBusy = false
			if u.m.vpnMeasured {
				// A live refresh finished first; its pool is newer than this
				// probe's cached copy.
				return
			}
			u.m.vpnMeasured = true
			u.m.vpnNodes = nodes
			u.m.vpnCountries = vpnGateCountries(nodes)
			u.invalidate()
		})
	}()
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

// probeCore stats the core binary and, when present, asks it which protocols
// it can actually parse (`mihomo -t` on a minimal config per protocol). The
// result drives the protocol tiles (unsupported ones are visibly marked) and
// the version line. Runs off the GUI thread; probeCoreCapabilities caches, so
// repeat calls are cheap.
func (u *natUI) probeCore() {
	dir, err := coreDir()
	if err != nil {
		return
	}
	u.sync(func() { u.refreshCoreCard(dir) })
	bin := core.CoreInDir(dir)
	if _, err := os.Stat(bin); err != nil {
		return // not installed yet; doCore re-probes after the download
	}
	ver, supported, perr := probeCoreCapabilities(bin, dir)
	u.sync(func() {
		u.m.coreVersion = ver
		u.m.capab = supported
		if perr != nil {
			u.addLog("Core 能力探测失败: "+perr.Error(), true)
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
	cs, ok := cachedScanFor(proto, false)
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

func (u *natUI) appendLog(text string, lv int, core, stage bool) {
	// The full session log is kept: copy, diagnostics and scrollback must be
	// able to reach every line, so dropping old entries here silently shortened
	// exactly the history a failed connect needs.
	u.m.logs = append(u.m.logs, natLog{at: time.Now(), text: text, lv: lv, core: core, stage: stage})
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
			if !protoV6Capable(p) && m.set.IPFamily != famV4 {
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
		m.psiphon = !m.psiphon
		// The two exits replace the same thing; enabling one turns the other
		// off instead of letting a file/UI carry both.
		if m.psiphon {
			m.openvpn = false
		}
		u.invalidate()
		// Hot switch, like the protocol chips: a live connection swaps its exit
		// without making the user disconnect by hand first.
		if m.connected && !protoChained(m.proto) && !m.working && !m.connecting {
			u.doSwitch()
		}
	case id == "openvpn":
		if protoChained(m.proto) {
			return
		}
		m.openvpn = !m.openvpn
		if m.openvpn {
			m.psiphon = false
		}
		u.invalidate()
		if m.openvpn {
			// The dropdown needs the pool; the cached list usually answers
			// instantly, a stale one refreshes in the background.
			u.refreshVPNGatePool()
		}
		if m.connected && !m.working && !m.connecting {
			u.doSwitch()
		}
	case id == "drop:region", id == "drop:vpnregion", id == "drop:proto", id == "drop:family", id == "drop:preset":
		which := strings.TrimPrefix(id, "drop:")
		if m.dropOpen == which {
			m.dropOpen = ""
		} else {
			m.dropOpen = which
			if which == "vpnregion" {
				m.vpnScroll = 0
				if len(m.vpnCountries) == 0 {
					u.refreshVPNGatePool()
				} else if !m.vpnMeasured {
					u.probeVPNGateLatencyAsync()
				}
			}
		}
		u.debugLogf(fmt.Sprintf("action %s -> dropOpen=%q page=%q", id, m.dropOpen, m.page))
		u.invalidate()
	case id == "vpnrefresh":
		u.refreshVPNGatePool(true)
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
			if m.connected && m.psiphon && !protoChained(m.proto) && !m.working && !m.connecting {
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
		if f != famV4 && !protoV6Capable(m.proto) {
			u.addLog(trf("%s 不支持 IPv6：请先切换协议", protoDisplayName(m.proto)), true)
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
	// mutually exclusive: V2 wins when both somehow arrive set. Both need a
	// plain WG/AWG/MASQUE underlay, so they are ignored for a chain.
	switch {
	case m.openvpn && !protoChained(m.proto):
		o.openvpnMode = true
		o.openvpnRegion = m.set.OpenVPNRegion
		o.openvpnNodePin = m.set.OpenVPNNode
	case m.psiphon && !protoChained(m.proto):
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
	go func() {
		sc := bufio.NewScanner(pr)
		// Closing the read end unblocks the exec copier once the scanner exits
		// (window closed), so the pipe can never wedge the child's stdout.
		defer pr.Close()
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
			u.sync(func() { u.addLogFull(msg, lv, true) })
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
				if u.m.openvpn {
					// The connect refreshed and saved the pool; reload it so the
					// region dropdown offers the countries it just proved live.
					u.refreshVPNGatePool()
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
	u.debugLogf(fmt.Sprintf("down %d,%d -> %s", x, y, id))
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
			id == "vpnrefresh"
	case "proto":
		return id == "drop:proto" || strings.HasPrefix(id, "proto:")
	case "family":
		return id == "drop:family" || strings.HasPrefix(id, "pickfamily:")
	case "preset":
		return id == "drop:preset" || strings.HasPrefix(id, "pickpreset:")
	}
	return false
}

func (u *natUI) onMove(x, y int, b walk.MouseButton) {
	// Dragging the scrollbar owns the pointer until the button is released:
	// walk reports the held button on every move, so no MouseUp hook is needed.
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
	if u.m.page == pageLogs && u.m.logTab == "run" {
		rows := u.m.logVisibleRows
		if rows < 1 {
			rows = 1
		}
		max := len(u.m.logs) - rows
		if max < 0 {
			max = 0
		}
		u.m.logScroll -= delta / 40
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
	if u.m.page != pageNodes || u.m.nodeVisibleRows == 0 || y < u.sy(shellBodyY+52) {
		return
	}
	max := len(u.visibleNodeRows()) - u.m.nodeVisibleRows
	if max < 0 {
		max = 0
	}
	u.m.scroll -= delta / 40
	if u.m.scroll < 0 {
		u.m.scroll = 0
	}
	if u.m.scroll > max {
		u.m.scroll = max
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
	// A paint bug used to end the process: the panic unwinds through walk's
	// window procedure, and a windowsgui binary simply disappears with the log
	// saying nothing. One frame is not worth losing the session over.
	defer func() {
		if rec := recover(); rec != nil {
			paintPanics++
			if paintPanics <= 3 {
				u.appendLog(fmt.Sprintf("界面绘制异常（已跳过该帧）: %v", rec), 2, false, false)
			}
			err = nil
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
	// One scale for both axes, and the leftover space distributed as equal
	// margins. Scaling width and height independently (or top-left anchoring a
	// uniformly scaled grid) is what makes a maximised window look stretched or
	// lopsided; this keeps every gap, radius and glyph in the ratio it was
	// designed with.
	u.k = math.Min(float64(pxW)/1080.0, float64(pxH)/(700.0+capH))
	if u.k <= 0 {
		u.k = 1
	}
	// The grid is pinned to the left edge (a sidebar that floats away from the
	// window edge looks broken) and centred vertically, where the leftover shows
	// up as canvas either way. Horizontally it *grows*: dw is how many design
	// units fit across the window, so maximising widens the cards instead of
	// leaving a blank strip on the right.
	u.ox = 0
	u.oy = int((float64(pxH)-(700.0+capH)*u.k)/2 + 0.5)
	u.dw = float64(pxW) / u.k
	if u.dw < 1080 {
		u.dw = 1080
	}
	// Type follows the window, not the display: k already carries the DPI.
	dpi := c.DPI()
	if dpi <= 0 {
		dpi = 96
	}
	u.scaleFonts(u.k * 96.0 / float64(dpi))
	u.sp = u.sp[:0]

	if err := c.FillRectanglePixels(u.brush(th.window), walk.Rectangle{X: 0, Y: 0, Width: b.Width, Height: b.Height}); err != nil {
		return err
	}
	u.paintWallpaper(c, b.Width, b.Height)
	u.paintShell(c)
	return nil
}

func (u *natUI) measure(c *walk.Canvas, s string, f *walk.Font) int {
	b, _, _ := c.MeasureTextPixels(s, f, walk.Rectangle{X: 0, Y: 0, Width: 10000, Height: 200}, walk.TextSingleLine|walk.TextNoPrefix)
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
func localProbeClients() []*http.Client {
	clients := []*http.Client{{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}}
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
			if pu, perr := url.Parse(srv); perr == nil {
				clients = append(clients, &http.Client{
					Timeout:   6 * time.Second,
					Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
				})
			}
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
func localLanIP() string {
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

func osRegionCC() string {
	regionOnce.Do(func() {
		k32 := windows.NewLazySystemDLL("kernel32.dll")
		proc := k32.NewProc("GetUserDefaultGeoName")
		if err := proc.Find(); err != nil {
			return
		}
		buf := make([]uint16, 32)
		n, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if int32(n) <= 0 {
			return
		}
		name := windows.UTF16ToString(buf)
		// "CN", or occasionally "CN|China": only the code is of interest.
		if i := strings.IndexAny(name, "|,"); i > 0 {
			name = name[:i]
		}
		if len(name) == 2 {
			regionCC = strings.ToUpper(name)
		}
	})
	return regionCC
}

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

// coloFlag resolves a colo or country label to an ISO alpha-2 code for the
// flag painter. Two-letter values (the trace probe's country) pass through.
func coloFlag(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) == 2 {
		return v
	}
	return coloCountry[v]
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

func avgSamples(v []int64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s int64
	for _, x := range v {
		s += x
	}
	return float64(s) / float64(len(v))
}
