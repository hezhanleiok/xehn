package netstack

import "net"

// ForwardHandlers 是 tun2socks 的出口：栈收到「任意目的地址」的连接后，
// 交给宿主去拨（订阅出口里就是 mihomo 的 mixed-port）。
//
// 单独放在无 build tag 的文件里：forward.go 依赖 gVisor 的 forwarder
// （只在 unix 可编译），而这个类型要给各平台共享。
type ForwardHandlers struct {
	DialTCP func(dst string) (net.Conn, error)
	DialUDP func(dst string) (net.PacketConn, error)
}
