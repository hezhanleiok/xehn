//go:build !android

package warp

import (
	"errors"
	"syscall"
)

// 桌面平台没有 VpnService 会把自己的 socket 抓走，所以这里是空操作。
func protectControl(syscall.RawConn) error { return nil }

// 桌面平台没有 VpnService 交出来的 tun fd，也就没有需要兜底关闭的对象。
// 各平台的 syscall.Close 签名不一样（Windows 收 Handle），这里刻意不做转换。
func closeFD(int) error {
	return errors.New("当前平台没有 VpnService 的 tun fd")
}
