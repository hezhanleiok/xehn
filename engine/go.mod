module github.com/xhwarp/android-engine

// 1.26.3 是依赖里最高的 go 指令（usque / gvisor）。这里不能再高：Psiphon 的
// psiphon-tls 在 init 里用反射校验 crypto/tls.ConnectionState 的字段布局，
// Go 1.27 给它加了一个字段，校验直接 panic —— 所以引擎必须用 go1.26 构建
// （见 tools/build-engine.ps1 里的 GOTOOLCHAIN）。
go 1.26.3

tool golang.org/x/mobile/cmd/gobind

// 一个进程里同时装了两个 quic-go fork（官方 quic-go 供 MASQUE，Psiphon 的
// fork 供它的 QUIC 传输），它们各自按不同版本的 qpack API 调用。本地兼容副本
// 同时提供两套 API，原因与改动见 third_party/qpack/README.md。
replace github.com/quic-go/qpack => ./third_party/qpack

// tailscale/netlink 是 2021 年的 vishvananda/netlink 分叉，已经停在旧 API 上；
// 而 Psiphon 的 packet tunnel 会 import 它。新版 vishvananda/netlink 改了几个
// 结构体字段类型与函数签名，这里用一份修好类型转换的本地副本顶替。
// 改动只有 6 行，见 third_party/tailscale-netlink/README.md。
replace github.com/tailscale/netlink => ./third_party/tailscale-netlink

require (
	github.com/Diniboy1123/connect-ip-go v0.0.0-20260613064811-66cba32d7d33
	github.com/Diniboy1123/usque v1.5.1-0.20260720063354-6aa03fc97d12
	github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.0-20261005170059-d5b23279c4d2
	github.com/amnezia-vpn/amneziawg-go v0.2.20-0.20260709022233-c1e9bb3758e7
	github.com/metacubex/tls v0.1.8
	github.com/quic-go/quic-go v0.60.0
	github.com/rasky/go-lzo v0.0.0-20200203143853-96a758eda86e
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/Jigsaw-Code/outline-sdk v0.0.16 // indirect
	github.com/Psiphon-Labs/bolt v0.0.0-20260921192800-17f196515990 // indirect
	github.com/Psiphon-Labs/consistent v0.0.0-20240322131436-20aaa4e05737 // indirect
	github.com/Psiphon-Labs/covert-dtls v0.0.0-20260423180104-2d3b15cbc8be // indirect
	github.com/Psiphon-Labs/goptlib v0.0.0-20200406165125-c0e32a7a3464 // indirect
	github.com/Psiphon-Labs/pion-ice/v4 v4.0.0-20260423180031-37d6e92d021f // indirect
	github.com/Psiphon-Labs/pion-webrtc/v4 v4.0.0-20260423180049-7ff453f9681a // indirect
	github.com/Psiphon-Labs/psiphon-tls v0.0.0-20260612202619-4944f00a8304 // indirect
	github.com/Psiphon-Labs/quic-go v0.0.0-20250527153145-79fe45fb83b1 // indirect
	github.com/Psiphon-Labs/utls v1.1.1-0.20260729134728-7a1fc711853d // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f // indirect
	github.com/axiomhq/hyperloglog v0.2.6 // indirect
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61 // indirect
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.6.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9 // indirect
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/flynn/noise v1.0.1-0.20220214164934-d803f5c4b0f4 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a // indirect
	github.com/mattn/go-sqlite3 v1.14.50 // indirect
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/miekg/dns v1.1.56 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pion/datachannel v1.6.0 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/interceptor v0.1.44 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.10.1 // indirect
	github.com/pion/sctp v1.9.2 // indirect
	github.com/pion/sdp/v3 v3.0.18 // indirect
	github.com/pion/srtp/v3 v3.0.10 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v2 v2.2.3 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v4 v4.1.4 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/conjure v0.7.11-0.20240130155008-c8df96195ab2 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/gotapdance v1.7.10 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	github.com/refraction-networking/utls v1.3.3 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8 // indirect
	github.com/tailscale/netlink v1.1.1-0.20211101221916-cabfb018fe85 // indirect
	github.com/txthinking/runnergroup v0.0.0-20250224021307-5864ffeb65ae // indirect
	github.com/txthinking/socks5 v0.0.0-20260601051520-339b044ab0eb // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gvisor.dev/gvisor v0.0.0-20260616165937-8e4bc62602eb // indirect
	tailscale.com v1.58.2 // indirect
)
