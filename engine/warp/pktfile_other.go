//go:build !android

package warp

import "os"

// packetFile 在桌面/自测平台就是普通文件：没有 VpnService，也就没有"Java 侧
// 持有 fd"这回事，Close 会真的关掉它。
type packetFile struct {
	file *os.File
}

func newPacketFile(fd int) *packetFile {
	return &packetFile{file: os.NewFile(uintptr(fd), "tun")}
}

func (p *packetFile) FD() int { return int(p.file.Fd()) }

func (p *packetFile) Read(b []byte) (int, error)  { return p.file.Read(b) }
func (p *packetFile) Write(b []byte) (int, error) { return p.file.Write(b) }
func (p *packetFile) Close() error                { return p.file.Close() }
