//go:build !android

package warp

import (
	"errors"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// The VpnService-fd device only exists on Android. Desktop builds (the local
// live tests run on Windows) keep using the gVisor netstack, so asking for fd
// mode here is a programming error rather than a silent downgrade: a silent
// fallback would report "connected" while the OS routes nothing, which is the
// exact bug this path was written to fix.
var errTunFDUnsupported = errors.New("VpnService tun fd 只在 Android 上可用")

func newFdTunDevice(int, int) (tun.Device, tunCounter, error) {
	return nil, nil, errTunFDUnsupported
}
