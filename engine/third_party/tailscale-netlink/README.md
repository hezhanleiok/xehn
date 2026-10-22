# tailscale/netlink（本地兼容副本）

**为什么会有这个目录：`github.com/tailscale/netlink` 停在了 2021 年的
`github.com/vishvananda/netlink` API 上，而我们别处的依赖强制了新版。**

- 引入者是 **Psiphon 的 packet tunnel**：
  `psiphon/common/tun`（我们就是靠它把系统 tun fd 交给 Psiphon 的）import 了
  `github.com/tailscale/netlink`。这是 `github.com/tailscale/netlink` 唯一的上游。
- 依赖冲突：`tailscale/netlink` 的 `xfrm_policy_linux.go` 直接 import
  `github.com/vishvananda/netlink/nl`，而模块图里的 vishvananda/netlink 是 v1.3.1
  （amneziawg-go / usque 那条线需要的版本）。v1.3.1 里：

  1. `nl.TcSfqQopt.Quantum` / `.Divisor` 从 `uint8` 变成 `uint32`（内核里本来就是
     32 位）；
  2. `(*nl.XfrmAddress).ToIPNet(prefixlen)` 变成 `ToIPNet(prefixlen, family uint16)`。

本目录是 `tailscale/netlink@v1.1.1-0.20211101221916-cabfb018fe85` 的整份拷贝，
**只改了 6 行**（都是补类型转换/补参数，没有改逻辑）：

| 文件 | 改动 |
|---|---|
| `qdisc_linux.go` | `addSfqData`：`uint32(qdisc.Quantum)`、`uint32(qdisc.Divisor)` |
| `qdisc_linux.go` | `parseSfqData`：`uint8(opt.TcSfqQopt.Quantum)`、`uint8(opt.TcSfqQopt.Divisor)` |
| `xfrm_policy_linux.go` | `ToIPNet(..., uint16(family))`（两处） |

升级 vishvananda/netlink 时，多半只需要把同样的 6 处再对一遍。
