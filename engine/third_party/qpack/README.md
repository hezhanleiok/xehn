# qpack（本地兼容副本）

**为什么会有这个目录：一个进程里要同时装两个 quic-go fork，而它们要求不同版本的
`github.com/quic-go/qpack`。**

- MASQUE 走官方 `github.com/quic-go/quic-go`（v0.60.0，经 `usque` 引入），
  它按 **qpack v0.6** 的形状调用：`NewDecoder()` + `Decode(p) DecodeFunc`。
- Psiphon 走它自己的 fork `github.com/Psiphon-Labs/quic-go`
  （v0.0.0-20250527153145），它按 **qpack v0.5** 的形状调用：
  `NewDecoder(emitFunc)` + `DecodeFull(p) ([]HeaderField, error)`。

两者是同一个模块路径，Go 的模块图只允许一个版本，而这两个 API 又互不兼容
（`NewDecoder` 参数个数不同，`Decode` / `DecodeFull` 各缺一边），所以任何
`replace ... => qpack vX` 都会让另一边编译不过。

这里把 **qpack v0.6.0 的源码整体拷进来**（MIT，见 `LICENSE.md`），只加了两处：

1. `NewDecoder` 改成可变参数 `NewDecoder(emitFunc ...func(HeaderField))` ——
   `NewDecoder()` 与 `NewDecoder(cb)` 两种调用都能编译。
2. 补回 v0.5 的 `DecodeFull(p) ([]HeaderField, error)`，直接驱动 v0.6 的
   `Decode` 状态机把整块解完。

编码侧（`Encoder`）两个版本本来就完全一致，一字未改。

升级 qpack 时：把新版源码重新拷进来，再按上面两条重做一遍即可。
