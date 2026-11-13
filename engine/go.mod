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
	github.com/metacubex/mihomo v1.19.32
	github.com/metacubex/tls v0.1.8
	github.com/quic-go/quic-go v0.60.0
	github.com/rasky/go-lzo v0.0.0-20200203143853-96a758eda86e
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	gvisor.dev/gvisor v0.0.0-20260616165937-8e4bc62602eb
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
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/armon/go-proxyproto v0.0.0-20180202201750-5b7edb60ff5f // indirect
	github.com/axiomhq/hyperloglog v0.2.6 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61 // indirect
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.6.0 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgraph-io/badger v1.5.4-0.20180815194500-3a87f6d9c273 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/dlclark/regexp2 v1.12.0 // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/easytier/easytier/easytier-go v0.0.0-20260910071355-3d0c9c3ca5e2 // indirect
	github.com/enfein/mieru/v3 v3.38.0 // indirect
	github.com/ericlagergren/aegis v0.0.0-20250325060835-cd0defd64358 // indirect
	github.com/ericlagergren/polyval v0.0.0-20220411101811-e25bc10ba391 // indirect
	github.com/ericlagergren/siv v0.0.0-20220507050439-0b757b3aa5f1 // indirect
	github.com/ericlagergren/subtle v0.0.0-20220507045147-890d697da010 // indirect
	github.com/flynn/noise v1.0.1-0.20220214164934-d803f5c4b0f4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grafov/m3u8 v0.0.0-20171211212457-6ab8f28ed427 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20250109001534-8abf58130905 // indirect
	github.com/josharian/native v1.1.1-0.20230202152459-5c7d0dd6ab86 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/klauspost/reedsolomon v1.12.3 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/marusama/semaphore v0.0.0-20171214154724-565ffd8e868a // indirect
	github.com/mattn/go-sqlite3 v1.14.50 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/metacubex/age v0.0.0-20260603010618-28d156b4ea78 // indirect
	github.com/metacubex/amneziawg-go v0.0.0-20260908071407-0c1c6f40ecd7 // indirect
	github.com/metacubex/ascon v0.1.0 // indirect
	github.com/metacubex/bart v0.29.0 // indirect
	github.com/metacubex/bbolt v0.0.0-20260706163408-d4ec34ad7c48 // indirect
	github.com/metacubex/blake3 v0.1.0 // indirect
	github.com/metacubex/chacha v0.1.5 // indirect
	github.com/metacubex/chi v0.1.1 // indirect
	github.com/metacubex/connect-ip-go v0.0.0-20260727083417-67ccdb0cf771 // indirect
	github.com/metacubex/cpu v0.1.2 // indirect
	github.com/metacubex/edwards25519 v1.2.0 // indirect
	github.com/metacubex/fswatch v0.1.1 // indirect
	github.com/metacubex/gopacket v1.1.20-0.20230608035415-7e2f98a3e759 // indirect
	github.com/metacubex/gvisor v0.0.0-20260922041103-e2cbcd6e7400 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/http v0.1.8 // indirect
	github.com/metacubex/jls-quic-go v0.0.0-20260727080412-732f2fc9a34d // indirect
	github.com/metacubex/jls-tls v0.0.0-20260723084315-67adc0e2f796 // indirect
	github.com/metacubex/jsonv2 v0.0.0-20260721082349-16b4998c8f89 // indirect
	github.com/metacubex/kcp-go v0.0.0-20260105040817-550693377604 // indirect
	github.com/metacubex/mhurl v0.1.0 // indirect
	github.com/metacubex/mipstack v0.0.0-20260930071539-961d4b1c1983 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/nftables v0.0.0-20260426003805-208c2c1ba2cb // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	github.com/metacubex/restls-client-go v0.1.9 // indirect
	github.com/metacubex/sevenzip v1.6.4 // indirect
	github.com/metacubex/sing v0.5.8 // indirect
	github.com/metacubex/sing-mux v0.3.12 // indirect
	github.com/metacubex/sing-quic v0.0.0-20260904234848-1c242664697a // indirect
	github.com/metacubex/sing-shadowsocks v0.2.13 // indirect
	github.com/metacubex/sing-shadowsocks2 v0.2.8 // indirect
	github.com/metacubex/sing-tun v0.4.27 // indirect
	github.com/metacubex/sing-vmess v0.2.5 // indirect
	github.com/metacubex/sing-wireguard v0.0.0-20260826105301-c3ae17d19f9e // indirect
	github.com/metacubex/smux v0.0.0-20260105030934-d0c8756d3141 // indirect
	github.com/metacubex/ssh v0.1.0 // indirect
	github.com/metacubex/tailscale v0.0.0-20260821153257-ff0ecd818181 // indirect
	github.com/metacubex/tailscale-wireguard-go v0.0.0-20260725073821-e61ab99cede2 // indirect
	github.com/metacubex/tfo-go v0.0.0-20260623020846-376a77860b8c // indirect
	github.com/metacubex/utls v1.8.8 // indirect
	github.com/metacubex/wazero v0.0.0-20260628025728-9ae6bdcf2a7d // indirect
	github.com/metacubex/wireguard-go v0.0.0-20250820062549-a6cecdd7f57f // indirect
	github.com/metacubex/yamux v0.0.0-20250918083631-dd5f17c0be49 // indirect
	github.com/metacubex/zerotier-go v0.0.0-20260813124750-13fa6f45da5f // indirect
	github.com/miekg/dns v1.1.63 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/mroth/weightedrand/v2 v2.1.0 // indirect
	github.com/oasisprotocol/deoxysii v0.0.0-20220228165953-2091330c22b7 // indirect
	github.com/openacid/low v0.1.21 // indirect
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
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
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/shadowsocks/go-shadowsocks2 v0.1.5 // indirect
	github.com/sina-ghaderi/poly1305 v0.0.0-20220724002748-c5926b03988b // indirect
	github.com/sina-ghaderi/rabaead v0.0.0-20220730151906-ab6e06b96e8c // indirect
	github.com/sina-ghaderi/rabbitio v0.0.0-20220730151941-9ce26f4f872e // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	github.com/stangelandcl/ppmd v0.1.1 // indirect
	github.com/syndtr/gocapability v0.0.0-20170704070218-db04d3cc01c8 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/netlink v1.1.1-0.20211101221916-cabfb018fe85 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/txthinking/runnergroup v0.0.0-20250224021307-5864ffeb65ae // indirect
	github.com/txthinking/socks5 v0.0.0-20260601051520-339b044ab0eb // indirect
	github.com/u-root/uio v0.0.0-20230305220412-3e8cd9d6bf63 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	tailscale.com v1.58.2 // indirect
)
