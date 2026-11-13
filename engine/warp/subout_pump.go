package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/net/proxy"

	netstackx "github.com/xhwarp/android-engine/warp/netstackx"
)

// SubOutExit 是「订阅出口」的数据面：
//
//	系统 tun(fd) ──► gVisor 栈 ──► mihomo mixed-port(SOCKS) ──► 订阅节点
//
// 为什么不用 mihomo 自带的 tun：它在 Android 上会读 /data/system/packages.xml
// 建 UID 规则，非 root 必然失败且不降级（真机日志：
// `Start TUN listening error: ... permission denied`），数据面因此完全不存在。
type SubOutExit struct {
	file packetStream
	dev  tun.Device
	once sync.Once
	// 双向包计数（诊断用，见 start 里的定时上报）。
	rxPkts atomic.Int64
	txPkts atomic.Int64
}

// StartSubOutPump 把 tun fd 接到 mihomo 的 mixed-port（socksAddr）上。
//
// dnsAddr 是 mihomo 的 DNS 监听（127.0.0.1:port）：tun2socks 把 UDP:53 全部
// 转给它，其余 UDP 直接拒绝（QUIC 会自动回退 TCP）。
func StartSubOutPump(fd int, socksAddr, dnsAddr string, report func(string)) (*SubOutExit, error) {
	if report == nil {
		report = func(string) {}
	}
	if fd <= 0 {
		return nil, errors.New("没有 tun fd")
	}
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 客户端初始化失败: %w", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 拨号器不支持 ContextDialer")
	}

	dev, _, err := netstackx.CreateNetTUNForwarding(
		[]netip.Addr{netip.MustParseAddr("172.16.0.2")}, nil, 1280, 4<<20,
		netstackx.ForwardHandlers{
			DialTCP: func(dst string) (net.Conn, error) {
				return cd.DialContext(context.Background(), "tcp", dst)
			},
			DialUDP: func(dst string) (net.PacketConn, error) {
				// 只处理 DNS：统一转给内核自己的 DNS 监听。
				// net.Dial("udp") 返回的是 *UDPConn（有 ReadFrom/WriteTo），
				// 但静态类型是 net.Conn，需要显式转换。
				if dnsAddr == "" {
					return nil, errors.New("没有 DNS 监听")
				}
				c, err := net.Dial("udp", dnsAddr)
				if err != nil {
					return nil, err
				}
				if pc, ok := c.(net.PacketConn); ok {
					return pc, nil
				}
				_ = c.Close()
				return nil, errors.New("UDP 连接不支持 PacketConn")
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("tun2socks 栈创建失败: %w", err)
	}

	e := &SubOutExit{file: newPacketFile(fd), dev: dev}
	e.start()
	// 前 60 秒每 5 秒报一次计数：这是区分「tun 上根本没包」和「栈把包丢了」的
	// 唯一办法 —— 已经靠猜修过太多次，不能再没有可观测性。
	go func() {
		for i := 0; i < 12; i++ {
			time.Sleep(5 * time.Second)
			report(fmt.Sprintf("tun2socks：tun→栈 %d 包，栈→tun %d 包",
				e.rxPkts.Load(), e.txPkts.Load()))
		}
	}()
	return e, nil
}

func (e *SubOutExit) start() {
	// tun → 栈
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := e.file.Read(buf)
			if n > 0 {
				e.rxPkts.Add(1)
				_, _ = e.dev.Write([][]byte{buf[:n]}, 0)
			}
			if err != nil {
				return
			}
		}
	}()
	// 栈 → tun
	go func() {
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, 2048)
		sizes := make([]int, 1)
		for {
			n, err := e.dev.Read(bufs, sizes, 0)
			if n > 0 {
				e.txPkts.Add(int64(n))
				for i := 0; i < n; i++ {
					_, _ = e.file.Write(bufs[i][:sizes[i]])
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// Close 停掉两端的泵（fd 的所有权在 Kotlin 侧，这里只停自己的循环）。
func (e *SubOutExit) Close() {
	e.once.Do(func() {
		if e.dev != nil {
			_ = e.dev.Close()
		}
		_ = e.file.Close()
	})
}

var _ = io.EOF
