//go:build !android

package netstack

import (
	"errors"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// CreateNetTUNForwarding 在非 Android 平台不可用。
//
// gVisor 的 tcp/udp forwarder 依赖 pkg/errors/linuxerr（unix.Errno 只在 unix 定义），
// Windows 上编不过。tun2socks 只在订阅出口用，而订阅出口只在 Android 上跑，
// 所以这里给一个能编译的 stub —— 引擎的 Windows 单测仍然可以正常跑。
func CreateNetTUNForwarding(
	localAddresses, dnsServers []netip.Addr, mtu, maxBuffer int, h ForwardHandlers,
) (tun.Device, *Net, error) {
	return nil, nil, errors.New("tun2socks 只在 Android 上可用")
}
