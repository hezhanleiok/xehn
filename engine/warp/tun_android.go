//go:build android

package warp

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fdTunDevice wraps the tun device Android's VpnService already created into an
// amneziawg-go tun.Device.
//
// This file exists because amneziawg-go ships tun_darwin / tun_linux /
// tun_windows and nothing for Android (verified against the module cache). An
// app cannot open /dev/net/tun and configure addresses itself: VpnService owns
// the interface, hands the app an fd, and the routing table, the addresses and
// the DNS servers are all decided in the VpnService.Builder. So this device does
// no ioctl at all - it is purely the data path, exactly like wireguard-android's
// tun.CreateTUNFromFile wrapper.
//
// fd 的所有权：**VpnService 的 ParcelFileDescriptor 拥有它，本设备只借用**。
// Close 不会关闭 fd（原因见 pktfile_android.go 的 fdsan 记录）。
type fdTunDevice struct {
	file   *packetFile
	mtu    int
	events chan tun.Event

	// Counters for the home screen's up/down throughput. Written from the
	// device's read and write goroutines, read by the engine's status sampler.
	txBytes atomic.Uint64 // packets written into the tun = traffic leaving the phone
	rxBytes atomic.Uint64 // packets read from the tun = traffic arriving

	closeOnce sync.Once
}

const fdTunName = "tun"

func newFdTunDevice(fd, mtu int) (tun.Device, tunCounter, error) {
	if fd <= 0 {
		return nil, nil, fmt.Errorf("无效的 tun fd: %d", fd)
	}
	if mtu <= 0 {
		mtu = tunnelMTU
	}
	d := &fdTunDevice{
		file:   newPacketFile(fd),
		mtu:    mtu,
		events: make(chan tun.Event, 4),
	}
	// The interface is already up: VpnService.Builder.establish() returned a
	// configured device. wireguard-go waits for this event before it starts
	// sending, and without it the handshake never leaves the phone - which
	// looks exactly like "connected but no traffic".
	d.events <- tun.EventUp
	return d, d, nil
}

// File 恒为 nil：tun 接口要求这个方法，但这里的 fd 属于 VpnService 的
// ParcelFileDescriptor，引擎不持有、也不应该把它交出去（谁拿到谁就可能 close）。
func (d *fdTunDevice) File() *os.File { return nil }

// BatchSize is 1: a phone has one queue and little memory, and batching buys
// nothing on a link whose packets are encrypted one by one anyway.
func (d *fdTunDevice) BatchSize() int { return 1 }

func (d *fdTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	n, err := d.file.Read(bufs[0][offset:])
	if n > 0 {
		sizes[0] = n
		d.rxBytes.Add(uint64(n))
	}
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (d *fdTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		n, err := d.file.Write(buf[offset:])
		if n > 0 {
			d.txBytes.Add(uint64(n))
		}
		if err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *fdTunDevice) MTU() (int, error) { return d.mtu, nil }

func (d *fdTunDevice) Name() (string, error) { return fdTunName, nil }

func (d *fdTunDevice) Events() <-chan tun.Event { return d.events }

func (d *fdTunDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.file.Close()
		close(d.events)
	})
	return err
}

// Counters reports cumulative bytes since the device was created.
func (d *fdTunDevice) Counters() (tx, rx uint64) {
	return d.txBytes.Load(), d.rxBytes.Load()
}
