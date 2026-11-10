package warp

import "net/netip"

// IPv4 源/目的地址替换（包泵里的「一对一 NAT」）。
//
// 背景（2026-11-10 真机日志）：VPN Gate 节点下发的是 10.211.x.x/32，而 10.0.0.0/8
// 同时是家用宽带与运营商 CGNAT 最常用的网段。物理网卡上已经有这个网段时，Android
// 的 Vpn.jniSetAddresses 会直接抛 IllegalArgumentException("Cannot set address")，
// **前缀放宽也没用**（/32、/24、/16 全被拒），系统 VPN 根本建不起来。
//
// 解决办法：tun 上放一个永远不可能冲突的地址（192.0.2.0/24 是 RFC 5737 保留的
// TEST-NET-1，任何真实网络都不会用它），然后在包泵里把源地址换成节点下发的那个。
// 对节点来说我们的源地址没变，回程 NAT 照旧；对本机来说地址永远不会撞车。
//
// 只处理 IPv4：OpenVPN 节点下发的就是 v4，v6 在系统 tun 里是 fail-closed 的。

// ipv4AddrBytes 把 netip.Addr 转成 4 字节；不是 IPv4 就返回 false。
func ipv4AddrBytes(a netip.Addr) ([4]byte, bool) {
	var out [4]byte
	if !a.Is4() {
		return out, false
	}
	out = a.As4()
	return out, true
}

// rewriteIPv4Addr 把 pkt 的源地址（isSrc=true）或目的地址从 from 改成 to。
//
// 返回是否真的改过 —— 调用方据此跳过无关报文（例如普通用户走的是「节点下发地址」
// 那条路径，此时这里永远匹配不上，等于没有这个函数）。
func rewriteIPv4Addr(pkt []byte, isSrc bool, from, to netip.Addr) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	f, ok := ipv4AddrBytes(from)
	if !ok {
		return false
	}
	t, ok := ipv4AddrBytes(to)
	if !ok {
		return false
	}
	off := 12
	if !isSrc {
		off = 16
	}
	if pkt[off] != f[0] || pkt[off+1] != f[1] || pkt[off+2] != f[2] || pkt[off+3] != f[3] {
		return false
	}
	copy(pkt[off:off+4], t[:])
	fixIPv4HeaderChecksum(pkt)

	// 传输层校验和的伪首部里也含地址，只有「第一个分片」才带 L4 头。
	// 注意不能用 MF 位判断：MF=1 且片偏移=0 的仍然是首片（带 L4 头）。
	if (uint16(pkt[6]&0x1F)<<8 | uint16(pkt[7])) != 0 {
		return true
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return true
	}
	l4 := pkt[ihl:]
	src := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}
	dst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	switch pkt[9] {
	case 6:
		fixTCPChecksum(l4, src, dst)
	case 17:
		fixUDPChecksum(l4, src, dst)
	}
	return true
}

// fixIPv4HeaderChecksum 重算 IPv4 头校验和（20–60 字节，便宜）。
func fixIPv4HeaderChecksum(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	pkt[10], pkt[11] = 0, 0
	s := ^fold16(onesSum(0, pkt[:ihl]))
	pkt[10], pkt[11] = byte(s>>8), byte(s)
}

// fixTCPChecksum 重算 TCP 校验和（伪首部 + 整段）。
func fixTCPChecksum(tcp []byte, src, dst [4]byte) {
	if len(tcp) < 20 {
		return
	}
	tcp[16], tcp[17] = 0, 0
	var sum uint32
	sum = onesSum(sum, src[:])
	sum = onesSum(sum, dst[:])
	sum += 6
	sum += uint32(len(tcp))
	sum = onesSum(sum, tcp)
	s := ^fold16(sum)
	tcp[16], tcp[17] = byte(s>>8), byte(s)
}

// fixUDPChecksum 重算 UDP 校验和；IPv4 下校验和为 0 表示「未计算」，保持不管。
func fixUDPChecksum(udp []byte, src, dst [4]byte) {
	if len(udp) < 8 || udp[6] == 0 && udp[7] == 0 {
		return
	}
	udp[6], udp[7] = 0, 0
	var sum uint32
	sum = onesSum(sum, src[:])
	sum = onesSum(sum, dst[:])
	sum += 17
	sum += uint32(len(udp))
	sum = onesSum(sum, udp)
	s := ^fold16(sum)
	if s == 0 { // 计算结果为 0 时要写成 0xFFFF
		s = 0xFFFF
	}
	udp[6], udp[7] = byte(s>>8), byte(s)
}

// onesSum 把 b 按 16 位大端累加（奇数长度补 0），返回未折叠的 32 位和。
func onesSum(sum uint32, b []byte) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	return sum
}

// fold16 把 32 位和折叠成 16 位（反码和）。
func fold16(sum uint32) uint16 {
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return uint16(sum)
}
