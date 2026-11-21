//go:build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/lxn/walk"

	"github.com/xhwarp/warp-client/internal/core"
)

// ---------------------------------------------------------------------------
// Modal dialogs
// ---------------------------------------------------------------------------

// dialogSurface is the modal dialogs' background: the same near-white the
// window's cards use, so a prompt looks like a piece of this app rather than a
// bare Win32 box dropped on top of it.
func dialogSurface() walk.Color { return rx(248, 249, 252) }

// styleDialog gives a modal the app's icon and a caption tinted like the dialog
// surface. The caller owns the returned icon and disposes it after the dialog.
func styleDialog(dlg *walk.Dialog) *walk.Icon {
	if dlg == nil {
		return nil
	}
	styleDialogChrome(uintptr(dlg.Handle()))
	src := logoImage()
	if src == nil {
		return nil
	}
	icon, err := walk.NewIconFromImage(resizeImage(src, 64, 64))
	if err != nil {
		return nil
	}
	_ = dlg.SetIcon(icon)
	return icon
}

// promptText shows a modal input box and returns the entered text. It runs on
// the GUI thread (actions always do), which is what walk's modal loop needs.
func (u *natUI) promptText(title, hint, value string) (string, bool) {
	return u.promptTextCheck(title, hint, value, nil)
}

// promptTextCheck is promptText with inline validation: a bad port or an
// unparseable DNS address is reported inside the dialog and the dialog stays
// open, instead of closing and answering only in the log panel.
func (u *natUI) promptTextCheck(title, hint, value string, validate func(string) error) (string, bool) {
	dlg, err := walk.NewDialogWithFixedSize(u.mw)
	if err != nil {
		u.addLog(tr("打开输入框失败")+": "+err.Error(), true)
		return "", false
	}
	bg, _ := walk.NewSolidColorBrush(dialogSurface())
	if bg != nil {
		dlg.SetBackground(bg)
	}
	icon := styleDialog(dlg)
	defer func() {
		dlg.Dispose()
		if icon != nil {
			icon.Dispose()
		}
		if bg != nil {
			bg.Dispose()
		}
	}()
	dlg.SetTitle(title)

	vbox := walk.NewVBoxLayout()
	_ = vbox.SetMargins(walk.Margins{HNear: 24, VNear: 18, HFar: 24, VFar: 16})
	_ = vbox.SetSpacing(8)
	if err := dlg.SetLayout(vbox); err != nil {
		u.addLog(tr("输入框布局失败")+": "+err.Error(), true)
		return "", false
	}

	// The caption already carries the title; the body only needs the hint, so
	// the dialog does not say the same thing twice.
	if hint != "" {
		if lbl, lerr := walk.NewLabel(dlg); lerr == nil {
			_ = lbl.SetText(hint)
			lbl.SetTextColor(rx(96, 104, 120))
		}
	}
	spacerLine, _ := walk.NewSpacerWithCfg(dlg, &walk.SpacerCfg{
		LayoutFlags: walk.ShrinkableVert,
		SizeHint:    walk.Size{Height: 4},
	})
	_ = spacerLine

	le, err := walk.NewLineEdit(dlg)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return "", false
	}
	_ = le.SetText(value)
	le.SetMaxLength(512)
	le.SetTextColor(rx(28, 32, 40))
	// One field width for every prompt: the dialog's width then depends on the
	// app, not on how long the value happens to be.
	_ = le.SetMinMaxSize(walk.Size{Width: 420, Height: 26}, walk.Size{Width: 420})

	errLabel, _ := walk.NewLabel(dlg)
	if errLabel != nil {
		_ = errLabel.SetText(" ")
		errLabel.SetTextColor(rx(198, 60, 60))
	}

	row, err := walk.NewComposite(dlg)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return "", false
	}
	hbox := walk.NewHBoxLayout()
	_ = hbox.SetMargins(walk.Margins{})
	_ = hbox.SetSpacing(8)
	_ = row.SetLayout(hbox)
	if sp, serr := walk.NewHSpacer(row); serr == nil {
		_ = sp
	}

	ok, err := walk.NewPushButton(row)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return "", false
	}
	_ = ok.SetText(tr("确定"))
	_ = ok.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	cancel, err := walk.NewPushButton(row)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return "", false
	}
	_ = cancel.SetText(tr("取消"))
	_ = cancel.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	_ = dlg.SetDefaultButton(ok)
	_ = dlg.SetCancelButton(cancel)

	// accepted holds exactly what validation approved. Returning le.Text()
	// instead let the two disagree — an IME committing its composition while the
	// dialog closes changes the control's text after the check — and the caller
	// then saved a value the dialog had never validated ("5200 is not a number?").
	accepted := value
	submit := func() {
		// Fold full-width digits and punctuation first: a Chinese IME produces
		// "５２００", which looks identical to 5200 and fails every numeric parse.
		txt := normalizeFieldInput(le.Text())
		if txt != le.Text() {
			_ = le.SetText(txt)
			le.SetTextSelection(len([]rune(txt)), len([]rune(txt)))
		}
		if validate != nil {
			if verr := validate(txt); verr != nil {
				if errLabel != nil {
					_ = errLabel.SetText("⚠ " + verr.Error())
				}
				le.SetFocus()
				return
			}
		}
		accepted = txt
		dlg.Accept()
	}
	ok.Clicked().Attach(submit)
	cancel.Clicked().Attach(func() { dlg.Cancel() })
	le.SetFocus()
	// Preselect the current value: typing then replaces it. Without this a user
	// who types a new port appends to the old one ("7890" + "17890"), the
	// validator rejects the result, and the dialog looks like it ignored the
	// click because nothing on the page changed.
	le.SetTextSelection(0, len([]rune(value)))

	if dlg.Run() != walk.DlgCmdOK {
		return "", false
	}
	return accepted, true
}

// normalizeFieldInput maps the characters a Chinese IME inserts onto their
// ASCII twins. Full-width digits are the important case: they render exactly
// like 5200, so "the port must be a number" reads as nonsense to the user who
// just typed a number.
func normalizeFieldInput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '\uFF10' && r <= '\uFF19': // ０-９
			b.WriteRune('0' + (r - '\uFF10'))
		case r == '\u3000': // ideographic space
			b.WriteRune(' ')
		case r == '\uFF0C' || r == '\u3001': // ，、
			b.WriteRune(',')
		case r == '\uFF0E': // ．
			b.WriteRune('.')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// confirm shows a yes/no dialog. The OK button carries the affirmative answer so
// Enter accepts and Esc cancels, which is what the keyboard expects.
func (u *natUI) confirm(title, question string) bool {
	dlg, err := walk.NewDialogWithFixedSize(u.mw)
	if err != nil {
		u.addLog(tr("打开对话框失败")+": "+err.Error(), true)
		return false
	}
	bg, _ := walk.NewSolidColorBrush(dialogSurface())
	if bg != nil {
		dlg.SetBackground(bg)
	}
	icon := styleDialog(dlg)
	defer func() {
		dlg.Dispose()
		if icon != nil {
			icon.Dispose()
		}
		if bg != nil {
			bg.Dispose()
		}
	}()
	dlg.SetTitle(title)

	vbox := walk.NewVBoxLayout()
	_ = vbox.SetMargins(walk.Margins{HNear: 24, VNear: 18, HFar: 24, VFar: 16})
	_ = vbox.SetSpacing(8)
	if err := dlg.SetLayout(vbox); err != nil {
		return false
	}
	if lbl, lerr := walk.NewLabel(dlg); lerr == nil {
		_ = lbl.SetText(question)
		_ = lbl.SetMinMaxSize(walk.Size{Width: 420}, walk.Size{Width: 420})
	}

	row, err := walk.NewComposite(dlg)
	if err != nil {
		return false
	}
	hbox := walk.NewHBoxLayout()
	_ = hbox.SetMargins(walk.Margins{})
	_ = hbox.SetSpacing(8)
	_ = row.SetLayout(hbox)
	if sp, serr := walk.NewHSpacer(row); serr == nil {
		_ = sp
	}

	ok, err := walk.NewPushButton(row)
	if err != nil {
		return false
	}
	_ = ok.SetText(tr("确定"))
	_ = ok.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	cancel, err := walk.NewPushButton(row)
	if err != nil {
		return false
	}
	_ = cancel.SetText(tr("取消"))
	_ = cancel.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	_ = dlg.SetDefaultButton(ok)
	_ = dlg.SetCancelButton(cancel)
	ok.Clicked().Attach(func() { dlg.Accept() })
	cancel.Clicked().Attach(func() { dlg.Cancel() })

	return dlg.Run() == walk.DlgCmdOK
}

// infoDialog is the app's one-button notice: a headline, a few short lines and
// a single acknowledgement. Lines are kept short on purpose — walk labels do
// not wrap, so a long paragraph would be clipped rather than reflowed.
func (u *natUI) infoDialog(title, headline string, lines []string) {
	dlg, err := walk.NewDialogWithFixedSize(u.mw)
	if err != nil {
		u.addLog(tr("打开对话框失败")+": "+err.Error(), true)
		return
	}
	bg, _ := walk.NewSolidColorBrush(dialogSurface())
	if bg != nil {
		dlg.SetBackground(bg)
	}
	icon := styleDialog(dlg)
	defer func() {
		dlg.Dispose()
		if icon != nil {
			icon.Dispose()
		}
		if bg != nil {
			bg.Dispose()
		}
	}()
	dlg.SetTitle(title)

	vbox := walk.NewVBoxLayout()
	_ = vbox.SetMargins(walk.Margins{HNear: 24, VNear: 18, HFar: 24, VFar: 16})
	_ = vbox.SetSpacing(8)
	if err := dlg.SetLayout(vbox); err != nil {
		return
	}

	if headline != "" {
		if lbl, lerr := walk.NewLabel(dlg); lerr == nil {
			_ = lbl.SetText(headline)
			_ = lbl.SetMinMaxSize(walk.Size{Width: 460}, walk.Size{Width: 460})
		}
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if lbl, lerr := walk.NewLabel(dlg); lerr == nil {
			_ = lbl.SetText(line)
			_ = lbl.SetMinMaxSize(walk.Size{Width: 460}, walk.Size{Width: 460})
			lbl.SetTextColor(rx(96, 104, 120))
		}
	}

	row, err := walk.NewComposite(dlg)
	if err != nil {
		return
	}
	hbox := walk.NewHBoxLayout()
	_ = hbox.SetMargins(walk.Margins{})
	_ = hbox.SetSpacing(8)
	_ = row.SetLayout(hbox)
	if sp, serr := walk.NewHSpacer(row); serr == nil {
		_ = sp
	}
	ok, err := walk.NewPushButton(row)
	if err != nil {
		return
	}
	_ = ok.SetText(tr("我已知晓"))
	_ = ok.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	_ = dlg.SetDefaultButton(ok)
	_ = dlg.SetCancelButton(ok)
	ok.Clicked().Attach(func() { dlg.Accept() })

	dlg.Run()
}

// showStartupNotice is the licence reminder every launch opens with: the
// project is free and open source, and selling it is not allowed.
func (u *natUI) showStartupNotice() {
	u.infoDialog(tr("使用须知"), tr("本软件开源免费，仅供学习交流使用，禁止售卖！"), []string{
		tr("本程序只在你自己的设备上配置一条加密隧道，"),
		tr("不提供、不代理任何服务器资源，请遵守当地法律法规。"),
		"",
		tr("如果你是通过付费渠道拿到本软件的，说明你被骗了；"),
		tr("请到项目主页免费下载：") + shortURL(repoURL),
	})
}

// controlStoppedDialog explains a remote stop: what happened, which code this
// install reports, and where to ask about it.
func (u *natUI) controlStoppedDialog() {
	msg := strings.TrimSpace(u.m.control.Message)
	if msg == "" {
		msg = defaultStopMessage
	}
	u.infoDialog(tr("客户端已停用"), msg, []string{
		tr("控制码：") + u.m.set.ControlCode,
		tr("如有疑问，请到项目主页反馈：") + shortURL(repoIssuesURL),
	})
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

// openURL hands a URL to the shell's default handler.
func openURL(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// openDir reveals a path in Explorer; a file is revealed by selecting it.
func openDir(path string) {
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		_ = exec.Command("explorer", "/select,"+path).Start()
		return
	}
	_ = exec.Command("explorer", path).Start()
}

func (u *natUI) openDataDir() {
	dir, err := appDir()
	if err != nil {
		u.addLog(err.Error(), true)
		return
	}
	openDir(dir)
}

// noticeFilePath / opensNotice used to reveal THIRD_PARTY_NOTICES.md from the
// program folder. The About page now links to the copy in the repository
// instead: a local path is meaningless on another machine, in a screenshot, or
// after a portable ZIP has been unpacked somewhere else.

// diagText is what the diagnostics button copies: everything needed to describe
// this install without asking the user to hunt through folders.
// diagHeader is the environment half of the diagnostic snapshot: versions,
// paths and the recorded connection state.
func (u *natUI) diagHeader() string {
	dir, _ := appDir()
	sp, _ := settingsPath()
	cDir, _ := coreDir()
	var b strings.Builder
	b.WriteString(productName + " " + shortVersion() + "\r\n")
	b.WriteString("build: " + guiBuildKind() + "\r\n")
	b.WriteString("lang/theme: " + u.m.set.Lang + " / " + u.m.set.Theme + "\r\n")
	b.WriteString("data: " + dir + "\r\n")
	b.WriteString("core: " + core.CoreInDir(cDir) + "\r\n")
	b.WriteString("core version: " + u.m.coreVersion + "\r\n")
	b.WriteString("settings: " + sp + "\r\n")
	if st, err := loadState(); err == nil {
		b.WriteString("state: " + st.statusLine() + "\r\n")
	}
	return b.String()
}

// diagText is the full snapshot the copy action puts on the clipboard.
func (u *natUI) diagText() string {
	var b strings.Builder
	b.WriteString(u.diagHeader())
	b.WriteString(u.logText())
	return b.String()
}

// ---------------------------------------------------------------------------
// Autostart (HKCU\...\Run) — the registry is the source of truth
// ---------------------------------------------------------------------------

const (
	autoRunKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoRunValue = "WARPClient"
)

func setAutoStart(enabled bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, autoRunKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !enabled {
		if err := k.DeleteValue(autoRunValue); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Quoted: the path may contain spaces, and Run parses it as a command line.
	return k.SetStringValue(autoRunValue, strconv.Quote(exe))
}

func autoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, autoRunKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if _, _, err := k.GetStringValue(autoRunValue); err != nil {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Preference plumbing shared by every page
// ---------------------------------------------------------------------------

// persistSession copies the session choices into the preference file and saves
// it, so a protocol or switch the user picked survives the process. Called when
// a connect starts and when the window closes.
func (u *natUI) persistSession() {
	m := u.m
	m.set.Proto = m.proto
	m.set.Pin = m.pin
	m.set.Psiphon = m.psiphon
	m.set.OpenVPN = m.openvpn
	m.set.OuterProto = m.outerProto
	m.set.InnerProto = m.innerProto
	if err := saveSettings(m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
}

// mutateSettings applies fn to the persisted preferences, saves them and marks
// the session as needing a reconnect (a live session read its settings when it
// started; changing them now cannot reach it).
func (u *natUI) mutateSettings(fn func(*clientSettings)) {
	fn(&u.m.set)
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	} else if u.m.connected {
		u.m.setDirty = true
	}
	u.invalidate()
}

// ---------------------------------------------------------------------------
// Small display helpers
// ---------------------------------------------------------------------------

func guiBuildKind() string {
	if windowsGUIBuild == "1" {
		return "Windows GUI (windowsgui)"
	}
	return "Windows console"
}

func coreSizeText(n int64) string {
	if n <= 0 {
		return tr("未知")
	}
	return sizeText(n)
}

func orEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// shortVersion is what the header and the about card call this build. A local,
// untagged build reports "dev", which would otherwise render as "vdev".
func shortVersion() string {
	if v := resolveVersion(); v != "dev" {
		return "v" + v
	}
	return tr("开发版")
}
