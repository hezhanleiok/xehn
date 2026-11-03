//go:build android

package warp

import (
	"io"
	"sync/atomic"
	"syscall"
)

// packetFile 读写一个**由 Java 侧（VpnService 的 ParcelFileDescriptor）拥有**的
// tun fd，并且**从不关闭它**。
//
// 为什么改成这样（2026-11-03 真机 SIGABRT）：
//
//	以前是 Kotlin `pfd.detachFd()` 之后把裸 fd 交给 os.NewFile，由 Go 关。
//	真机日志里稳定复现 fdsan abort：
//	  fdsan: failed to exchange ownership of file descriptor: fd 193 is owned by
//	  unique_fd 0x..., was expected to be unowned
//	原因是同一个 tun fd 的"所有权"被两边各记了一份：Java 的 ParcelFileDescriptor
//	带 fdsan tag，Go 这边是裸 fd 直接 close。一旦某次 establish / 换点让 fd 号被
//	内核复用，下一次 ParcelFileDescriptor 操作就会撞上"这个 fd 已经有主了" →
//	abort（SIGABRT，Java 层 try/catch 抓不到，只能直接闪退）。
//
// 现在的模型只有一条：**fd 的创建者（Kotlin 的 ParcelFileDescriptor）负责关闭**，
// Go 只是借用读写。Java 一 close，这里的阻塞 Read 立刻返回 EBADF，泵自己退出。
//
// 顺带的好处：Devices 不再需要 ClaimTunFD/ReleaseTunFD 那套全局记账（那套标志位
// 一旦置 true 就再也不会复位，第二次连接起就完全失效）。
type packetFile struct {
	fd     int
	closed atomic.Bool
}

func newPacketFile(fd int) *packetFile {
	return &packetFile{fd: fd}
}

// FD 是底层 fd 号（只读用，切勿拿它去 close）。
func (p *packetFile) FD() int { return p.fd }

func (p *packetFile) Read(b []byte) (int, error) {
	for {
		if p.closed.Load() {
			return 0, io.EOF
		}
		n, err := syscall.Read(p.fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			// tun 读到 0 字节只可能是对端（内核）已经关掉它。
			return 0, io.EOF
		}
		return n, nil
	}
}

func (p *packetFile) Write(b []byte) (int, error) {
	for {
		if p.closed.Load() {
			return 0, io.EOF
		}
		n, err := syscall.Write(p.fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return n, err
		}
		return n, nil
	}
}

// Close 只让自己这边的读写停下来，**不关 fd**：fd 归 VpnService 的
// ParcelFileDescriptor，由 Kotlin 的 closeTun() 关闭。
func (p *packetFile) Close() error {
	p.closed.Store(true)
	return nil
}
