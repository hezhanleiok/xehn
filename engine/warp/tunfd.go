package warp

// tunCounter 是「能报出累计收发字节的 tun 设备」这一能力。
//
// 它存在的原因：数据面有两种形态 —— 系统 VPN 的 fd 设备（fdTunDevice）与进程内
// netstack。只有前者能自己数包，所以计数器按接口取，取不到就当 0（见
// Session.Counters 与首页的上下行速率 / 总量）。桌面版是去读 mihomo 的 /traffic，
// 安卓这边没有 mihomo，只能从设备本身数。
type tunCounter interface {
	Counters() (tx, rx uint64)
}
