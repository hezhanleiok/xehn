//go:build windows

package main

import (
	"time"

	"github.com/lxn/walk"
)

// The tray icon is what makes "close the window" mean "keep the tunnel up".
// A VPN client that exits when its window closes drops the system proxy and
// every connection with it, so the X button parks the window here and the tray
// menu is the only place that really quits — the behaviour v2rayN users expect.

// initTray creates the icon, its menu and the click handler. Called once, after
// the window exists; a failure is logged and the client keeps working with the
// plain close-to-exit behaviour.
func (u *natUI) initTray() {
	u.trayAttempts = 0
	u.tryInitTray()
}

// tryInitTray creates the icon, retrying a few times: Shell_NotifyIcon fails
// when the shell is still starting up (a fresh logon, an Explorer restart, a
// busy taskbar), and the failure is transient in exactly those cases. If every
// attempt fails the client keeps working, but closing the window then exits for
// real — hiding a window that has no icon anywhere would leave a process the
// user cannot reach.
func (u *natUI) tryInitTray() {
	if u.ni != nil || u.quitting {
		return
	}
	ni, err := walk.NewNotifyIcon(u.mw)
	if err != nil {
		u.trayAttempts++
		if u.trayAttempts < 5 {
			time.AfterFunc(400*time.Millisecond, func() { u.sync(u.tryInitTray) })
			return
		}
		u.trayFailed = true
		u.addLog(tr("创建托盘图标失败: ")+err.Error()+tr("；关闭窗口将直接退出程序"), true)
		return
	}
	u.ni = ni

	if src := logoImage(); src != nil {
		// 32px covers the 16/20/24/32 sizes Explorer asks for at every DPI.
		if icon, ierr := walk.NewIconFromImage(resizeImage(src, 32, 32)); ierr == nil {
			_ = ni.SetIcon(icon)
		}
	}
	_ = ni.SetToolTip(productName)

	// Left click (and the double click Explorer synthesises) brings the window
	// back; the menu is on the right button, which walk shows by itself.
	ni.MouseDown().Attach(func(x, y int, btn walk.MouseButton) {
		if btn == walk.LeftButton {
			u.showFromTray()
		}
	})

	actions := ni.ContextMenu().Actions()
	show := walk.NewAction()
	_ = show.SetText(tr("显示主窗口"))
	show.Triggered().Attach(u.showFromTray)
	actions.Add(show)

	quit := walk.NewAction()
	_ = quit.SetText(tr("退出"))
	quit.Triggered().Attach(u.quitApp)
	actions.Add(quit)

	if err := ni.SetVisible(true); err != nil {
		u.trayFailed = true
		u.addLog(tr("创建托盘图标失败: ")+err.Error()+tr("；关闭窗口将直接退出程序"), true)
	}
}

// showFromTray restores the window and brings it to the foreground. Show alone
// is not enough once another window has focus: the taskbar button comes back
// but the window can stay behind, so it is activated explicitly.
func (u *natUI) showFromTray() {
	if u.mw == nil {
		return
	}
	u.mw.Show()
	_ = u.mw.Activate()
	u.invalidate()
}

// trayHint tells the user where the window went the first time they close it,
// so "the program disappeared" never becomes a support question.
func (u *natUI) trayHint() {
	if u.ni == nil {
		return
	}
	_ = u.ni.ShowInfo(tr("仍在后台运行"), tr("窗口已收进系统托盘，隧道保持连接；右键托盘图标可以退出。"))
}

// quitApp is the tray menu's exit action.
func (u *natUI) quitApp() { u.quitNow() }

// quitNow is the only path that really exits: it sets the flag the closing
// handler checks, drops the tray icon and closes the window, after which the
// normal teardown (proxy restore, core stop) runs.
//
// The dispose and the close happen after this handler returns, on the next
// turn of the GUI loop. Doing them inline deadlocked: Disposing the NotifyIcon
// destroys the popup menu TrackPopupMenu is still pumping, that loop never
// comes back, and the process stayed in Task Manager with no window and no
// icon — exactly the reported "退出 didn't quit".
func (u *natUI) quitNow() {
	u.quitting = true
	if u.ni != nil {
		// Hide first: the shell drops the icon at once, so the click has a
		// visible effect even if the teardown takes a moment.
		_ = u.ni.SetVisible(false)
	}
	if u.quitScheduled {
		return
	}
	u.quitScheduled = true
	go func() {
		time.Sleep(150 * time.Millisecond)
		u.sync(func() {
			if u.ni != nil {
				u.ni.Dispose()
				u.ni = nil
			}
			if u.mw != nil {
				u.mw.Close()
			}
		})
	}()
}
