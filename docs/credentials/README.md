# 真凭据（不入库）

这个仓库里**没有**下面两个文件。它们是真凭据，一旦提交就等于公开，所以写进了
`.gitignore`。没有它们 App 照样能装、能启动，只是这两条路走不通：

| 放这里 | 是什么 | 缺了会怎样 |
|---|---|---|
| `app/src/main/assets/account.json` | 随包内置的 WARP 设备账号（含私钥，还内嵌 `masque` / `outer` 两台附加设备） | 首次连接必须现场访问 `api.cloudflareclient.com` 注册；受限网络里几乎必然失败 |
| `app/src/main/assets/psiphon/client.config` | 官方 Psiphon 客户端配置（`SponsorId` / 服务器列表 URL / 签名公钥） | Psiphon 出口起不来，日志会写「缺少官方 client.config（SponsorId / 服务器列表 URL / 签名公钥都在里面）」 |

## 怎么拿到

**`account.json`** —— 字段形状见 [`account.json.example`](account.json.example)。两条路：

1. **在能连 Cloudflare 的网络里跑一次 App**：引擎注册成功后会把它写到
   `filesDir/engine/account.json`，即
   `/data/data/com.xiaohe.vpn/files/engine/account.json`。debug 包可以用
   `adb shell run-as com.xiaohe.vpn cat files/engine/account.json` 取出来。
   设置页「关于 → 内置账号」会显示这份账号有没有载入成功。
2. **在电脑上跑桌面版**（`d:\xhwarp`）的 `warpscout register`，用生成的
   `warpscout-account.json`（字段名一致）。

想要 `masque` / `outer` 两个子对象（这样 MASQUE 与 WARP-in-WARP 也不必现注册），
就得注册**三台**设备：MASQUE 的登记会把设备改成 `secp256r1`，外层设备必须是
另一台 —— Cloudflare 会丢掉「同一台设备嵌套自己」的流量。引擎会在
`SetAccountJSON` 时把这两个子对象拆成 `masque.json` / `outer.json` 落到工作目录。

**`client.config`** —— 从 Psiphon 官方渠道获取（赞助者/合作项目会提供一份
`client.config`）。放到 `app/src/main/assets/psiphon/client.config` 即可，
构建脚本不用改。

## 提交前自查

```powershell
git status --short                                          # 这两个文件不应出现
git ls-files | Select-String 'client.config|assets/account.json'   # 应当没有输出
```

（`docs/credentials/account.json.example` 是脱敏模板，可以入库；它里面没有任何真值。）
