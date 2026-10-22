//go:build android

package warp

import "syscall"

// protectControl excludes a socket from the VPN at the moment it is created.
//
// Doing it inside ListenConfig.Control (rather than after the fact) is the
// difference between working and not: an unprotected socket's first packet is
// already routed back into our own tun, so the handshake goes nowhere and the
// failure is invisible from the UI.
func protectControl(c syscall.RawConn) error {
	p := currentProtector()
	if p == nil {
		return nil
	}
	return c.Control(func(fd uintptr) {
		p.Protect(int(fd))
	})
}

// closeFD 关闭一个还没有被任何设备接管的 tun fd。见 tunfd.go 的所有权说明。
func closeFD(fd int) error {
	return syscall.Close(fd)
}
