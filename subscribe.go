package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// 设计意图与安全边界
//
// 本文件是订阅内容进入渲染层之前的唯一「消毒」入口：把来自任意来源（URL、
// Clash YAML、base64、纯文本 URI）的不可信输入，收敛成一组结构化的 ProxySpec。
//
//   - 一切外部输入都有体积上限，远端拉取再叠一层 SSRF 防护（禁内网/回环），
//     防止订阅服务被当成探测内网的跳板。
//   - 字段走「白名单 + 显式拒绝」双闸：既不让 dialer-proxy / interface-name /
//     routing-mark 之类能改写本机路由的键混进来，也不让 name/type 混进
//     Fields（它们单独进结构体），更不会把 Clash 顶层全局配置误当成节点字段。
//   - 节点名统一经 SafeProxyName 清洗，避免 YAML 注入字符与保留名冲突。
//   - 只依赖标准库 + yaml.v3，不引用项目内任何其它类型/函数，保持自包含。
// ---------------------------------------------------------------------------

const (
	maxSubscriptionBytes = 4 << 20 // 订阅输入上限 4MB
	maxFetchBytes        = 2 << 20 // 远端 body 上限 2MB
	// A public subconverter has to fetch the source subscription AND often a
	// remote config (e.g. raw.githubusercontent.com) before it can answer.
	// 15s was too tight and 502s from those backends are frequently transient,
	// so allow a longer single attempt and a couple of retries.
	defaultFetchTimeout      = 20 * time.Second
	subscriptionTotalTimeout = 50 * time.Second
	subscriptionMaxAttempts  = 3
)

// ProxySpec 是单个代理节点：Name/Type 单独成字段，其余配置全部落在 Fields。
// Fields 的值类型被约束为 string / int / bool / []any / map[string]any，
// 便于渲染层统一处理。
type ProxySpec struct {
	Name   string
	Type   string
	Fields map[string]any
	// DelayMS is the last measured HTTP round trip through this proxy via the
	// mihomo delay API. 0 means "not tested yet" — those sort to the end.
	DelayMS int `json:"delay_ms,omitempty"`
	// DelayErr marks a node that WAS tested and did not answer (timeout /
	// refused / blocked). Without it a failed node and an untested one both
	// carried DelayMS=0 and the list showed "—" for both, so the user could not
	// tell "not measured yet" from "dead".
	DelayErr bool `json:"delay_err,omitempty"`
	// CC is the ISO alpha-2 country the node's name advertises (a 🇺🇸 flag
	// emoji, a "US-" prefix, or a Chinese country word). Empty means unknown —
	// the card then draws no flag rather than a wrong one.
	CC string `json:"cc,omitempty"`
	// SubID links this node to the subscription it came from (SubSource.ID).
	// Empty means a legacy/orphan node imported before subscriptions had
	// identities; those show under "全部" and the ungrouped bucket.
	SubID string `json:"sub_id,omitempty"`
}

// SubSource is one remembered subscription: a stable identity plus the display
// name, group and origin the user manages. URL is empty for non-URL imports
// (file / clipboard / QR / single node), which cannot be re-fetched. Kind tells
// the refresh loop which sources are re-downloadable.
type SubSource struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	Group string `json:"group,omitempty"`
	Kind  string `json:"kind,omitempty"`
}

// ParsedInput 是一次订阅解析的结果，Source 标识识别到的输入形态。
type ParsedInput struct {
	Proxies []ProxySpec
	Source  string
}

// newSubID returns a collision-resistant subscription identity. It is stable for
// the life of the source so editing its name/group/URL never orphans its nodes.
func newSubID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on the supported platforms; fall back to a
		// time-derived id rather than panicking inside an import dialog.
		return "sub" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// subNameFromURL derives a default display name from a subscription URL: the
// host without its port, falling back to the whole URL when it cannot parse.
// The user can override it in the import dialog.
func subNameFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host
}

// ---------------------------------------------------------------------------
// 字段白名单 / 显式拒绝集合
// ---------------------------------------------------------------------------

// allowedFields 为「规范化后的键」集合。规范化规则见 normKey：小写、下划线转连字符。
// 既包含分享链接能映射出的 mihomo 字段，也包含常见 mihomo proxy 字段。
var allowedFields = map[string]bool{
	// 基础连接
	"server": true, "port": true, "cipher": true, "password": true, "uuid": true,
	"alterid": true, "network": true, "tls": true, "servername": true, "sni": true,
	"skip-cert-verify": true, "udp": true, "flow": true, "alpn": true,
	"path": true, "host": true, "headers": true,
	// ss / ssr
	"plugin": true, "plugin-opts": true, "protocol": true, "protocol-param": true,
	"obfs": true, "obfs-param": true, "obfs-password": true, "method": true,
	// vless / reality / vmess / trojan
	"client-fingerprint": true, "fingerprint": true, "reality-opts": true,
	"grpc-opts": true, "ws-opts": true, "h2-opts": true, "http-opts": true,
	"quic-opts": true, "grpc-service-name": true, "short-id": true,
	"spider-x": true, "mode": true, "packet-encoding": true,
	"global-padding": true, "authenticated-length": true,
	// hysteria2 / tuic
	"auth": true, "auth-str": true, "up": true, "down": true,
	"ca": true, "ca-str": true, "congestion-controller": true,
	"recv-window-conn": true, "recv-window": true, "disable-mtu-discovery": true,
	"cwnd": true, "max-open-streams": true, "heartbeat-interval": true,
	"hop-interval": true, "reduce-rtt": true, "request-timeout": true,
	"max-udp-relay-packet-size": true, "udp-relay-mode": true, "fast-open": true,
	// wireguard
	"private-key": true, "public-key": true, "pre-shared-key": true,
	"ip": true, "ipv6": true, "reserved": true, "mtu": true,
	"remote-dns-resolve": true, "local-address": true, "allowed-ips": true,
	"dns": true, "peers": true, "persistent-keepalive": true,
	// 其它常见字段
	"username": true, "tfo": true, "tcp-fast-open": true, "udp-over-tcp": true,
	"udp-over-tcp-version": true, "uot": true, "mptcp": true, "ip-version": true,
	"ecc": true, "allow-insecure": true,
}

// deniedFields 是「明确丢弃」的键。
//
// 说明：blacklist 里的 port / mixed-port / external-controller / proxy-groups /
// rules / tun 等，指的是 Clash 顶层全局配置键——ParseSubscription 只取 proxies
// 列表（规则 1），这些顶层键天然被丢弃；而每个节点自身的 server port 是白名单中
// 的核心字段，必须保留，否则节点不可用。dialer-proxy / interface-name /
// routing-mark 是能改写本机路由的危险节点字段，即便出现在节点里也强制剔除。
// name / type 被单独提取进 ProxySpec 结构体，不进入 Fields。
var deniedFields = map[string]bool{
	"dialer-proxy": true, "interface-name": true, "routing-mark": true,
	"tun": true, "proxy-groups": true, "rules": true,
	"external-controller": true, "mixed-port": true,
	"name": true, "type": true,
	"allow-lan": true, "bind-address": true, "external-ui": true,
	"secret": true, "sniffer": true,
}

// 少数 mihomo 字段是驼峰命名，规范化后需还原成规范键名。
var canonicalKeys = map[string]string{
	"alterid": "alterId",
}

// 需要整数化的字段（键用规范化形式）。
var intFields = map[string]bool{
	"port": true, "alterid": true, "mtu": true,
	"recv-window-conn": true, "recv-window": true, "max-open-streams": true,
	"cwnd": true, "heartbeat-interval": true, "hop-interval": true,
	"request-timeout": true, "max-udp-relay-packet-size": true,
	"persistent-keepalive": true,
}

// 需要布尔化的字段。
var boolFields = map[string]bool{
	"udp": true, "tls": true, "skip-cert-verify": true,
	"disable-mtu-discovery": true, "remote-dns-resolve": true,
	"udp-over-tcp": true, "uot": true, "tfo": true, "fast-open": true,
	"tcp-fast-open": true, "mptcp": true, "reduce-rtt": true,
	"global-padding": true, "authenticated-length": true,
	"allow-insecure": true,
}

// 需要按逗号拆成 []any 的字段。
var listFields = map[string]bool{
	"alpn": true, "local-address": true, "allowed-ips": true, "dns": true,
}

// 需要拆成整数列表的字段（如 wireguard reserved）。
var intListFields = map[string]bool{
	"reserved": true,
}

// 分享链接 query 中的非同名键 → 目标字段（值均为规范化键）。
// fp 是 uTLS 客户端指纹（chrome/firefox…），必须落到 client-fingerprint；
// fingerprint 是证书 SPKI 钉扎，把 "chrome" 填进去会让 CDN 前置的 TLS 握手失败。
var queryKeyAliases = map[string]string{
	"type": "network", "aid": "alterid", "method": "cipher",
	"fp": "client-fingerprint", "clientfingerprint": "client-fingerprint",
	"servicename": "grpc-service-name", "pbk": "public-key",
	"sid": "short-id", "spx": "spider-x",
	"allowinsecure": "skip-cert-verify", "insecure": "skip-cert-verify",
	"cca": "congestion-controller", "congestion": "congestion-controller",
	"upmbps": "up", "downmbps": "down", "obfspassword": "obfs-password",
	"authstr": "auth-str", "header": "headers",
}

// vmess base64 JSON 的键 → 目标字段（空串表示忽略）。
var vmessJSONAliases = map[string]string{
	"add": "server", "port": "port", "id": "uuid", "aid": "alterId",
	"scy": "cipher", "security": "cipher", "net": "network",
	"host": "host", "path": "path", "sni": "servername",
	"servername": "servername", "alpn": "alpn", "fp": "client-fingerprint",
	"headers": "headers", "v": "", "type": "",
}

// 支持的分享链接 scheme。
var supportedSchemes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true, "trojan": true,
	"hysteria2": true, "hy2": true, "tuic": true, "wireguard": true,
	"socks5": true, "http": true, "https": true,
}

var reservedNames = map[string]bool{
	"warp": true, "psiphon": true, "openvpn exit": true,
	// mihomo's own built-ins: a node carrying one of these names shadows the
	// outbound every rule falls back to.
	"direct": true, "reject": true, "global": true, "pass": true,
	"compatible": true, "probe": true, "sub-base": true, "sub-exit": true,
}

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------

func normKey(k string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "_", "-")
}

func canonicalKey(nk string) string {
	if c, ok := canonicalKeys[nk]; ok {
		return c
	}
	return nk
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// normalizeValue 把任意来源的值收敛到 string/int/bool/[]any/map[string]any。
func normalizeValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return x
	case bool:
		return x
	case int:
		return x
	case int8:
		return int(x)
	case int16:
		return int(x)
	case int32:
		return int(x)
	case int64:
		return int(x)
	case uint:
		return int(x)
	case uint8:
		return int(x)
	case uint16:
		return int(x)
	case uint32:
		return int(x)
	case uint64:
		return int(x)
	case float32:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		if i, e := x.Int64(); e == nil {
			return int(i)
		}
		if f, e := x.Float64(); e == nil {
			return int(f)
		}
		return x.String()
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeValue(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[toStr(k)] = normalizeValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeValue(vv)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = vv
		}
		return out
	default:
		return fmt.Sprint(x)
	}
}

// coerceVal 在 normalizeValue 之上，把字符串按字段语义转成 int/bool/列表。
func coerceVal(nk string, val any) any {
	v := normalizeValue(val)
	s, ok := v.(string)
	if !ok {
		return v
	}
	s = strings.TrimSpace(s)
	if intFields[nk] {
		if n, e := strconv.Atoi(s); e == nil {
			return n
		}
	}
	if boolFields[nk] {
		if b, e := strconv.ParseBool(s); e == nil {
			return b
		}
		switch strings.ToLower(s) {
		case "1", "yes", "on":
			return true
		case "0", "no", "off", "":
			return false
		}
	}
	if intListFields[nk] {
		parts := strings.Split(s, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if n, e := strconv.Atoi(p); e == nil {
				out = append(out, n)
			} else {
				out = append(out, p)
			}
		}
		return out
	}
	if listFields[nk] {
		parts := strings.Split(s, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return v
}

// putFieldN 以「已规范化键」写入一个字段，统一过白名单/黑名单闸。
// conv=true 时附带字符串→语义类型转换（URI query 场景），否则保留原类型（YAML 场景）。
func putFieldN(fields map[string]any, nk string, val any, conv bool) {
	if deniedFields[nk] || !allowedFields[nk] {
		return
	}
	ck := canonicalKey(nk)
	if conv {
		fields[ck] = coerceVal(nk, val)
	} else {
		fields[ck] = normalizeValue(val)
	}
}

func putField(fields map[string]any, key string, val any, conv bool) {
	putFieldN(fields, normKey(key), val, conv)
}

// toMap 兼容 yaml.v3 可能出现的 map[string]any 与 map[any]any。
func toMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, vv := range m {
			out[toStr(k)] = vv
		}
		return out, true
	default:
		return nil, false
	}
}

// decodeB64 兼容标准/URL-safe base64、有无 padding，并容忍空白字符。
func decodeB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, fmt.Errorf("empty base64")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	variants := []string{
		s,
		strings.NewReplacer("-", "+", "_", "/").Replace(s),
		strings.NewReplacer("+", "-", "/", "_").Replace(s),
	}
	lastErr := fmt.Errorf("invalid base64")
	for _, v := range variants {
		for _, enc := range encodings {
			if b, err := enc.DecodeString(v); err == nil {
				return b, nil
			} else {
				lastErr = err
			}
		}
		if m := len(v) % 4; m != 0 {
			padded := v + strings.Repeat("=", 4-m)
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				if b, err := enc.DecodeString(padded); err == nil {
					return b, nil
				} else {
					lastErr = err
				}
			}
		}
	}
	return nil, lastErr
}

func shortURI(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = nil // 错误前缀里不透出凭据
		s = u.String()
	}
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func nodeErr(orig string, err error) error {
	return fmt.Errorf("%s: %w", shortURI(orig), err)
}

// ---------------------------------------------------------------------------
// SafeProxyName
// ---------------------------------------------------------------------------

// sanitizeName 移除换行/冒号/#/引号/控制字符及其它 YAML 危险字符，仅保留安全字符。
func sanitizeName(s string) string {
	const danger = ":#\"'[]{}&*!|>,%@`"
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			b.WriteRune(' ')
		case strings.ContainsRune(danger, r):
			b.WriteRune(' ')
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func isReserved(s string) bool {
	return reservedNames[strings.ToLower(strings.TrimSpace(s))]
}

// ---------------------------------------------------------------------------
// Country detection from a node name
// ---------------------------------------------------------------------------

// nameCountryWords maps the country words subscriptions actually put in node
// names to an ISO alpha-2 code. Chinese first (the CN providers label nodes
// this way), English second.
var nameCountryWords = map[string]string{
	"美国": "US", "香港": "HK", "台湾": "TW", "日本": "JP", "新加坡": "SG",
	"韩国": "KR", "德国": "DE", "英国": "GB", "法国": "FR", "荷兰": "NL",
	"俄罗斯": "RU", "加拿大": "CA", "澳大利亚": "AU", "澳洲": "AU", "印度": "IN",
	"土耳其": "TR", "阿联酋": "AE", "越南": "VN", "泰国": "TH", "马来": "MY",
	"马来西亚": "MY", "印尼": "ID", "菲律宾": "PH", "巴西": "BR", "阿根廷": "AR",
	"墨西哥": "MX", "瑞士": "CH", "瑞典": "SE", "挪威": "NO", "芬兰": "FI",
	"丹麦": "DK", "波兰": "PL", "西班牙": "ES", "意大利": "IT", "葡萄牙": "PT",
	"爱尔兰": "IE", "奥地利": "AT", "比利时": "BE", "乌克兰": "UA", "以色列": "IL",
	"南非": "ZA", "埃及": "EG", "沙特": "SA", "哈萨克": "KZ", "澳门": "MO",
	"蒙古": "MN", "巴基斯坦": "PK", "柬埔寨": "KH", "缅甸": "MM", "尼泊尔": "NP",
	"斯里兰卡": "LK", "孟加拉": "BD", "捷克": "CZ", "希腊": "GR", "匈牙利": "HU",
	"罗马尼亚": "RO", "保加利亚": "BG", "克罗地亚": "HR", "塞尔维亚": "RS",
	"智利": "CL", "哥伦比亚": "CO", "秘鲁": "PE", "新西兰": "NZ", "伊朗": "IR",
	"伊拉克": "IQ", "卡塔尔": "QA", "科威特": "KW", "阿曼": "OM", "约旦": "JO",
	"亚美尼亚": "AM", "格鲁吉亚": "GE", "阿塞拜疆": "AZ", "白俄罗斯": "BY",
	"斯洛伐克": "SK", "斯洛文尼亚": "SI", "立陶宛": "LT", "拉脱维亚": "LV",
	"爱沙尼亚": "EE", "美国西部": "US", "美国东部": "US", "中国": "CN",
}

// nameCountryCodes is the allowlist for the "US-443-WS" prefix form. It is a
// list, not any two letters: "443-WS-TLS" contains WS (Samoa), "CF" and "CDN"
// are infrastructure words, and guessing from those would paint wrong flags.
var nameCountryCodes = map[string]bool{
	"US": true, "HK": true, "TW": true, "JP": true, "SG": true, "KR": true,
	"DE": true, "GB": true, "UK": true, "FR": true, "NL": true, "RU": true,
	"CA": true, "AU": true, "IN": true, "TR": true, "AE": true, "VN": true,
	"TH": true, "MY": true, "ID": true, "PH": true, "BR": true, "AR": true,
	"MX": true, "CH": true, "SE": true, "NO": true, "FI": true, "DK": true,
	"PL": true, "ES": true, "IT": true, "PT": true, "IE": true, "AT": true,
	"BE": true, "UA": true, "IL": true, "ZA": true, "EG": true, "SA": true,
	"KZ": true, "MO": true, "MN": true, "PK": true, "KH": true, "MM": true,
	"NP": true, "LK": true, "BD": true, "CZ": true, "GR": true, "HU": true,
	"RO": true, "BG": true, "HR": true, "RS": true, "CL": true, "CO": true,
	"PE": true, "NZ": true, "IR": true, "IQ": true, "QA": true, "KW": true,
	"OM": true, "JO": true, "AM": true, "GE": true, "AZ": true, "BY": true,
	"SK": true, "SI": true, "LT": true, "LV": true, "EE": true, "CN": true,
	"IS": true, "LU": true, "MT": true, "CY": true, "PR": true, "GU": true,
}

// stripFlagEmoji removes regional-indicator flag emoji from a name and returns
// the first country they encode. Subscriptions that render "🇺🇸 US-443-WS" put
// the country there; keeping the emoji would also paint a tofu box in the
// card, because the list draws its own flag chip.
func stripFlagEmoji(s string) (clean, cc string) {
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= 0x1F1E6 && r <= 0x1F1FF && i+1 < len(runes) &&
			runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
			if cc == "" {
				cc = string([]rune{'A' + (r - 0x1F1E6), 'A' + (runes[i+1] - 0x1F1E6)})
			}
			i++
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String()), cc
}

// countryFromName derives the country a node name advertises: flag emoji first,
// then a leading ISO code ("US-443-WS-TLS"), then a country word ("美国节点").
// It returns "" when the name says nothing — a neutral card beats a wrong flag.
func countryFromName(raw string) string {
	_, cc := stripFlagEmoji(raw)
	if cc != "" {
		if nameCountryCodes[cc] {
			return cc
		}
		return ""
	}
	// Leading / bracketed two-letter code, e.g. "US-443", "[SG] 节点", "jp01".
	upper := strings.ToUpper(raw)
	for _, sep := range []string{"-", "_", " ", "|", "]", "】", "·"} {
		if idx := strings.Index(upper, sep); idx == 2 && nameCountryCodes[upper[:2]] {
			return upper[:2]
		}
	}
	if len(upper) >= 2 && nameCountryCodes[upper[:2]] {
		// "JP01" / "SG443": a code glued to a digit is still a country tag.
		if len(upper) > 2 && upper[2] >= '0' && upper[2] <= '9' {
			return upper[:2]
		}
	}
	for word, code := range nameCountryWords {
		if strings.Contains(raw, word) {
			return code
		}
	}
	return ""
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if n < 1 {
		n = 1
	}
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// SafeProxyName 生成一个 YAML 安全、去重、避开保留名的节点名。
//
// prefix is empty for subscription imports: the name the provider shipped is
// what the user sees in every other Clash client, and a "SUB-" prefix on all
// 100+ nodes made the list unreadable.
func SafeProxyName(prefix, raw string, used map[string]bool) string {
	if used == nil {
		used = map[string]bool{}
	}
	base := sanitizeName(raw)
	if base == "" {
		base = "Node"
	}
	const maxLen = 48
	p := []rune(prefix)
	// 预留 "-NN" 去重后缀的空间
	room := maxLen - len(p) - 4
	if room < 1 {
		room = 1
	}
	base = truncateRunes(base, room)
	candidate := prefix + base
	if isReserved(candidate) || used[candidate] {
		for i := 2; ; i++ {
			suffix := "-" + strconv.Itoa(i)
			avail := maxLen - len(p) - len([]rune(suffix))
			nc := prefix + truncateRunes(base, avail) + suffix
			if !isReserved(nc) && !used[nc] {
				candidate = nc
				break
			}
		}
	}
	used[candidate] = true
	return candidate
}

// ---------------------------------------------------------------------------
// FetchSubscription
// ---------------------------------------------------------------------------

// isBlockedIP 拒绝内网/回环/链路本地/未指定地址。
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 0/8、10/8、127/8、172.16/12、192.168/16、169.254/16
		if ip4[0] == 0 || ip4[0] == 10 || ip4[0] == 127 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}

func checkHostSafe(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("fetch subscription: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("fetch subscription: no ip for %q", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return fmt.Errorf("fetch subscription: host %q resolves to blocked address %s", host, ip.IP)
		}
	}
	return nil
}

// FetchSubscription 仅允许 http/https，带超时、UA、2MB 限流与 SSRF 防护。
func FetchSubscription(ctx context.Context, rawURL string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = defaultFetchTimeout
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: bad url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("fetch subscription: only http/https allowed, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("fetch subscription: empty host")
	}
	if err := checkHostSafe(ctx, host); err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// A live subscription session is the one route that can reach a
			// converter domain the local network blocks: mihomo's mixed port
			// speaks HTTP CONNECT, so the same port works as an HTTP proxy.
			// Without a session the fetch stays direct.
			Proxy: func(*http.Request) (*url.URL, error) {
				st, serr := loadState()
				if serr != nil || !st.Connected || !st.SubMode || st.MixedPort <= 0 {
					return nil, nil
				}
				return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.MixedPort))
			},
			// 在真正拨号前重新解析并锁定到「已校验」的 IP，缓解 DNS rebinding。
			// 优先 IPv4：一些转换服务的 AAAA 记录指向不可达节点，选到它会
			// 直接拿到网关的 502，而同域名的 A 记录工作正常。
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				h, port, e := net.SplitHostPort(addr)
				if e != nil {
					return nil, e
				}
				ips, e := net.DefaultResolver.LookupIPAddr(dctx, h)
				if e != nil {
					return nil, e
				}
				var chosen, v6 net.IP
				for _, ip := range ips {
					if isBlockedIP(ip.IP) {
						continue
					}
					if ip.IP.To4() != nil {
						chosen = ip.IP
						break
					}
					if v6 == nil {
						v6 = ip.IP
					}
				}
				if chosen == nil {
					chosen = v6
				}
				if chosen == nil {
					return nil, fmt.Errorf("fetch subscription: host %q has no allowed ip", h)
				}
				d := &net.Dialer{Timeout: timeout}
				return d.DialContext(dctx, network, net.JoinHostPort(chosen.String(), port))
			},
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("fetch subscription: too many redirects")
			}
			return checkHostSafe(r.Context(), r.URL.Hostname())
		},
	}

	// Public subconverters answer 502 while their own upstream (the source
	// subscription or a remote config= URL) is slow or unreachable. Those are
	// transient: one retry a second later usually succeeds. Never retry a 4xx
	// that is the client's own fault.
	var lastErr error
	for attempt := 0; attempt < subscriptionMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("fetch subscription: %w", ctx.Err())
			case <-time.After(time.Duration(attempt) * 700 * time.Millisecond):
			}
		}
		body, retry, err := fetchSubscriptionOnce(ctx, client, rawURL, timeout)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	if lastErr == nil {
		return nil, fmt.Errorf("fetch subscription: no attempt made")
	}
	return nil, fmt.Errorf("%w | 订阅转换服务暂不可用（已尝试 %d 次）：请稍后重试、改用「文件导入」，或去掉链接中指向 GitHub 的 config= 参数", lastErr, subscriptionMaxAttempts)
}

// fetchSubscriptionOnce issues one GET. retryable is true for transport errors,
// 429 and 5xx, i.e. failures of the converter or its upstream rather than of
// the URL supplied by the user.
func fetchSubscriptionOnce(ctx context.Context, client *http.Client, rawURL string, timeout time.Duration) ([]byte, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("fetch subscription: %w", err)
	}
	req.Header.Set("User-Agent", "warp-client/1.0 (+subscription)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == 429 || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("fetch subscription: non-2xx status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("fetch subscription: read body: %w", err)
	}
	if len(body) > maxFetchBytes {
		return nil, false, fmt.Errorf("fetch subscription: body exceeds %d bytes", maxFetchBytes)
	}
	return body, false, nil
}

// ---------------------------------------------------------------------------
// ParseNodeURI
// ---------------------------------------------------------------------------

func fragmentName(u *url.URL) string {
	return u.Fragment // url.Parse 已做百分号解码
}

func setServerPort(fields map[string]any, u *url.URL) {
	if h := u.Hostname(); h != "" {
		putField(fields, "server", h, false)
	}
	if p := u.Port(); p != "" {
		putField(fields, "port", p, true)
	}
}

func copyQuery(fields map[string]any, q url.Values) {
	for k, vs := range q {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		nk := normKey(k)
		switch nk {
		case "encryption": // vless 固定 none，忽略
			continue
		case "security":
			sec := strings.ToLower(v)
			if sec != "none" && sec != "" {
				putFieldN(fields, "tls", true, false)
			}
			continue
		case "sni", "peer":
			putFieldN(fields, "servername", v, true)
			putFieldN(fields, "sni", v, true)
			continue
		}
		target := nk
		if a, ok := queryKeyAliases[nk]; ok {
			target = a
		}
		putFieldN(fields, target, v, true)
	}
}

func parseUserinfo(sp *ProxySpec, u *url.URL) {
	if u.User == nil {
		return
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	switch sp.Type {
	case "vless":
		putField(sp.Fields, "uuid", user, false)
	case "trojan", "hysteria2":
		putField(sp.Fields, "password", user, false)
	case "tuic":
		putField(sp.Fields, "uuid", user, false)
		if pass != "" {
			putField(sp.Fields, "password", pass, false)
		}
	case "wireguard":
		putField(sp.Fields, "private-key", user, false)
	case "socks5", "http":
		putField(sp.Fields, "username", user, false)
		if pass != "" {
			putField(sp.Fields, "password", pass, false)
		}
	}
}

func parseHierarchical(sp *ProxySpec, u *url.URL) error {
	sp.Name = fragmentName(u)
	setServerPort(sp.Fields, u)
	copyQuery(sp.Fields, u.Query())
	normalizeTransport(sp.Fields)
	parseUserinfo(sp, u)
	return nil
}

// normalizeTransport folds the flat query keys into the nested options mihomo
// actually reads.
//
// A vless://…?type=ws&path=/ws&host=cdn.example link used to come out as
//
//	network: ws
//	path: /ws
//	host: cdn.example
//
// mihomo ignores the last two — it only reads ws-opts.path and
// ws-opts.headers.Host — so the WebSocket upgrade never happens and every probe
// ends in "502 Bad Gateway" or a timeout, while v2rayN and Clash clients (which
// map the flat keys themselves) connect fine. That is exactly the report:
// "same subscription works everywhere else, 0/N here".
func normalizeTransport(fields map[string]any) {
	netw := strings.ToLower(strings.TrimSpace(fieldString(fields["network"])))
	switch netw {
	case "ws", "websocket":
		path := fieldString(fields["path"])
		host := fieldString(fields["host"])
		if path == "" && host == "" {
			return
		}
		opts, _ := fields["ws-opts"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		if path != "" {
			if _, ok := opts["path"]; !ok {
				opts["path"] = path
			}
		}
		if host != "" {
			headers, _ := opts["headers"].(map[string]any)
			if headers == nil {
				headers = map[string]any{}
			}
			if _, ok := headers["Host"]; !ok {
				headers["Host"] = host
			}
			opts["headers"] = headers
		}
		fields["ws-opts"] = opts
		delete(fields, "path")
		delete(fields, "host")
	case "grpc":
		svc := fieldString(fields["grpc-service-name"])
		if svc == "" {
			return
		}
		opts, _ := fields["grpc-opts"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		if _, ok := opts["grpc-service-name"]; !ok {
			opts["grpc-service-name"] = svc
		}
		fields["grpc-opts"] = opts
		delete(fields, "grpc-service-name")
	case "h2", "http":
		path := fieldString(fields["path"])
		host := fieldString(fields["host"])
		if path == "" && host == "" {
			return
		}
		opts, _ := fields["h2-opts"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		if path != "" {
			if _, ok := opts["path"]; !ok {
				opts["path"] = path
			}
		}
		if host != "" {
			if _, ok := opts["host"]; !ok {
				opts["host"] = []any{host}
			}
		}
		fields["h2-opts"] = opts
		delete(fields, "path")
		delete(fields, "host")
	}
}

func fieldString(v any) string {
	s, _ := v.(string)
	return s
}

// opaquePayload 取 scheme:// 之后、? 或 # 之前的部分（用于 base64 整体编码的链接）。
func opaquePayload(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "?#"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func parsePlugin(sp *ProxySpec, p string) {
	seg := strings.Split(p, ";")
	putField(sp.Fields, "plugin", seg[0], false)
	if len(seg) > 1 {
		opts := map[string]any{}
		for _, kv := range seg[1:] {
			if i := strings.IndexByte(kv, '='); i > 0 {
				opts[kv[:i]] = kv[i+1:]
			}
		}
		if len(opts) > 0 {
			sp.Fields["plugin-opts"] = normalizeValue(opts)
		}
	}
}

func parseSS(sp *ProxySpec, raw string, u *url.URL) error {
	sp.Name = fragmentName(u)
	q := u.Query()
	copyQuery(sp.Fields, q)
	if p := q.Get("plugin"); p != "" {
		parsePlugin(sp, p)
	}

	if u.User != nil {
		// SIP002: ss://base64(method:password)@host:port
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		var method, password string
		switch {
		case hasPass: // 明文 method:password
			method, password = user, pass
		default:
			dec, e := decodeB64(user)
			if e == nil && strings.Contains(string(dec), ":") {
				parts := strings.SplitN(string(dec), ":", 2)
				method, password = parts[0], parts[1]
			} else if parts := strings.SplitN(user, ":", 2); len(parts) == 2 {
				method, password = parts[0], parts[1]
			} else {
				method = user
			}
		}
		putField(sp.Fields, "cipher", method, false)
		putField(sp.Fields, "password", password, false)
		setServerPort(sp.Fields, u)
		return nil
	}

	// 旧式: ss://base64(method:password@host:port)
	pl := opaquePayload(raw)
	if u.RawQuery != "" { // 有些实现把 / 当作 query 前的分隔
		pl = strings.TrimSuffix(pl, "/")
	}
	dec, err := decodeB64(pl)
	if err != nil {
		return err
	}
	at := strings.LastIndex(string(dec), "@")
	if at < 0 {
		return fmt.Errorf("bad ss payload: missing @")
	}
	cred, dest := string(dec)[:at], string(dec)[at+1:]
	parts := strings.SplitN(cred, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("bad ss credential")
	}
	putField(sp.Fields, "cipher", parts[0], false)
	putField(sp.Fields, "password", parts[1], false)
	host, port, e := net.SplitHostPort(dest)
	if e != nil {
		if i := strings.LastIndexByte(dest, ':'); i > 0 {
			host, port = dest[:i], dest[i+1:]
		} else {
			return fmt.Errorf("bad ss server")
		}
	}
	putField(sp.Fields, "server", host, false)
	putField(sp.Fields, "port", port, true)
	return nil
}

func parseSSR(sp *ProxySpec, raw string, u *url.URL) error {
	pl := opaquePayload(raw)
	dec, err := decodeB64(pl)
	if err != nil {
		return err
	}
	text := string(dec)
	var mainPart, params string
	if i := strings.Index(text, "/?"); i >= 0 {
		mainPart, params = text[:i], text[i+2:]
	} else {
		mainPart = text
	}
	remarks := ""
	if params != "" {
		pq, _ := url.ParseQuery(params)
		if v := pq.Get("obfsparam"); v != "" {
			if d, e := decodeB64(v); e == nil {
				v = string(d)
			}
			putField(sp.Fields, "obfs-param", v, false)
		}
		if v := pq.Get("protoparam"); v != "" {
			if d, e := decodeB64(v); e == nil {
				v = string(d)
			}
			putField(sp.Fields, "protocol-param", v, false)
		}
		if v := pq.Get("remarks"); v != "" {
			if d, e := decodeB64(v); e == nil {
				remarks = string(d)
			} else {
				remarks = v
			}
		}
	}
	sp.Name = remarks
	if sp.Name == "" {
		sp.Name = fragmentName(u)
	}
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return fmt.Errorf("bad ssr payload")
	}
	n := len(parts)
	server := strings.Join(parts[:n-5], ":")
	port := parts[n-5]
	protocol := parts[n-4]
	cipher := parts[n-3]
	obfs := parts[n-2]
	passb64 := parts[n-1]
	password := passb64
	if d, e := decodeB64(passb64); e == nil {
		password = string(d)
	}
	putField(sp.Fields, "server", server, false)
	putField(sp.Fields, "port", port, true)
	putField(sp.Fields, "protocol", protocol, false)
	putField(sp.Fields, "cipher", cipher, false)
	putField(sp.Fields, "obfs", obfs, false)
	putField(sp.Fields, "password", password, false)
	return nil
}

func vmessFromJSON(sp *ProxySpec, m map[string]any) string {
	name := ""
	for k, v := range m {
		nk := normKey(k)
		if nk == "ps" {
			name = toStr(v)
			continue
		}
		if nk == "tls" {
			b := false
			switch vv := v.(type) {
			case bool:
				b = vv
			case string:
				b = vv == "tls" || vv == "true" || vv == "1"
			case float64:
				b = vv != 0
			}
			putFieldN(sp.Fields, "tls", b, false)
			continue
		}
		target := k
		if a, ok := vmessJSONAliases[nk]; ok {
			if a == "" {
				continue
			}
			target = a
		}
		putField(sp.Fields, target, v, true)
	}
	return name
}

func parseVmess(sp *ProxySpec, raw string, u *url.URL) error {
	pl := opaquePayload(raw)
	dec, err := decodeB64(pl)
	if err == nil {
		var m map[string]any
		if json.Unmarshal(dec, &m) == nil && len(m) > 0 {
			name := vmessFromJSON(sp, m)
			if name == "" {
				name = fragmentName(u)
			}
			sp.Name = name
			return nil
		}
	}
	// 带查询参数的形式：vmess://uuid@host:port?...
	sp.Name = fragmentName(u)
	setServerPort(sp.Fields, u)
	copyQuery(sp.Fields, u.Query())
	if u.User != nil {
		putField(sp.Fields, "uuid", u.User.Username(), false)
	}
	return nil
}

// ParseNodeURI 解析单个分享链接，返回结构化的 ProxySpec；解析不了返回带 URI 前缀的错误。
func ParseNodeURI(s string) (ProxySpec, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return ProxySpec{}, nodeErr(orig, fmt.Errorf("empty uri"))
	}
	u, err := url.Parse(s)
	if err != nil {
		return ProxySpec{}, nodeErr(orig, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if !supportedSchemes[scheme] {
		return ProxySpec{}, nodeErr(orig, fmt.Errorf("unsupported scheme %q", scheme))
	}

	sp := ProxySpec{Fields: map[string]any{}}
	switch scheme {
	case "hy2":
		sp.Type = "hysteria2"
	case "https":
		sp.Type = "http"
		putFieldN(sp.Fields, "tls", true, false)
	default:
		sp.Type = scheme
	}

	switch sp.Type {
	case "ss":
		err = parseSS(&sp, orig, u)
	case "ssr":
		err = parseSSR(&sp, orig, u)
	case "vmess":
		err = parseVmess(&sp, orig, u)
	default:
		err = parseHierarchical(&sp, u)
	}
	if err != nil {
		return ProxySpec{}, nodeErr(orig, err)
	}
	if toStr(sp.Fields["server"]) == "" {
		return ProxySpec{}, nodeErr(orig, fmt.Errorf("missing server"))
	}
	return sp, nil
}

// ---------------------------------------------------------------------------
// ParseSubscription
// ---------------------------------------------------------------------------

func singleURL(text string) string {
	if strings.ContainsAny(text, "\r\n") {
		return ""
	}
	lo := strings.ToLower(text)
	if !strings.HasPrefix(lo, "http://") && !strings.HasPrefix(lo, "https://") {
		return ""
	}
	u, err := url.Parse(text)
	if err != nil || u.Host == "" {
		return ""
	}
	// 带 userinfo 的更可能是 http(s) 代理节点，而非订阅地址
	if u.User != nil {
		return ""
	}
	return text
}

func splitLines(s string) []string {
	parts := strings.Split(s, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasSupportedScheme(line string) bool {
	i := strings.Index(line, "://")
	if i <= 0 {
		return false
	}
	return supportedSchemes[strings.ToLower(line[:i])]
}

// looksLikeURIList 判断 base64 解码结果是否为「一行行 URI」。
func looksLikeURIList(b []byte) ([]string, bool) {
	if !utf8.Valid(b) {
		return nil, false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return nil, false
		}
	}
	var out []string
	for _, l := range splitLines(string(b)) {
		if hasSupportedScheme(l) {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func parseURILines(lines []string) ([]ProxySpec, error) {
	var out []ProxySpec
	var firstErr error
	for _, l := range lines {
		if !hasSupportedScheme(l) {
			continue
		}
		sp, err := ParseNodeURI(l)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, sp)
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no valid proxy uri")
	}
	return out, nil
}

// specFromMap 把 YAML proxies 列表中的一项转成 ProxySpec：name/type 单独提取，
// 其余字段过白名单，值保留原类型。
func specFromMap(m map[string]any) ProxySpec {
	sp := ProxySpec{Fields: map[string]any{}}
	for k, v := range m {
		nk := normKey(k)
		if nk == "name" {
			sp.Name = toStr(v)
			continue
		}
		if nk == "type" {
			sp.Type = strings.ToLower(toStr(v))
			continue
		}
		putField(sp.Fields, k, v, false)
	}
	return sp
}

// finalize 统一为所有节点生成安全、去重、避开保留名的名字，并识别国家。
func finalize(in *ParsedInput) *ParsedInput {
	used := map[string]bool{}
	for i := range in.Proxies {
		p := &in.Proxies[i]
		raw := p.Name
		// The flag emoji is metadata, not part of the name: pull the country
		// out first, then clean the emoji away so the card can draw its own
		// flag chip instead of rendering a tofu box.
		if cc := countryFromName(raw); cc != "" {
			p.CC = cc
		}
		raw, _ = stripFlagEmoji(raw)
		if raw == "" {
			raw = toStr(p.Fields["server"])
		}
		if raw == "" {
			raw = p.Type
		}
		if raw == "" {
			raw = "Node"
		}
		p.Name = SafeProxyName("", raw, used)
		if p.CC == "" {
			p.CC = countryFromName(p.Name)
		}
	}
	return in
}

// ParseSubscription 自动识别订阅形态并解析，输入上限 4MB。
func ParseSubscription(raw []byte) (*ParsedInput, error) {
	return parseSubscription(raw, 0)
}

func parseSubscription(raw []byte, depth int) (*ParsedInput, error) {
	if depth > 3 {
		return nil, fmt.Errorf("parse subscription: too many nested url subscriptions")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("parse subscription: empty input")
	}
	if len(raw) > maxSubscriptionBytes {
		return nil, fmt.Errorf("parse subscription: input exceeds %d bytes", maxSubscriptionBytes)
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("parse subscription: empty input")
	}

	// ① 单个 http(s) URL → 拉取 body 再递归解析
	if sub := singleURL(text); sub != "" {
		ctx, cancel := context.WithTimeout(context.Background(), subscriptionTotalTimeout)
		defer cancel()
		body, err := FetchSubscription(ctx, sub, defaultFetchTimeout)
		if err != nil {
			return nil, err
		}
		in, err := parseSubscription(body, depth+1)
		if err != nil {
			return nil, err
		}
		in.Source = "url"
		return in, nil
	}

	// ② 完整 Clash YAML（含 proxies:）→ 只取 proxies 列表，忽略所有其它顶层键
	var top map[string]any
	if err := yaml.Unmarshal(raw, &top); err == nil && top != nil {
		if arr, ok := top["proxies"].([]any); ok {
			proxies := make([]ProxySpec, 0, len(arr))
			for _, it := range arr {
				if m, ok := toMap(it); ok {
					proxies = append(proxies, specFromMap(m))
				}
			}
			return finalize(&ParsedInput{Proxies: proxies, Source: "yaml"}), nil
		}
	}

	// ③ base64 解码后得到一行行 URI
	if dec, err := decodeB64(text); err == nil {
		if lines, ok := looksLikeURIList(dec); ok {
			if proxies, err := parseURILines(lines); err == nil {
				return finalize(&ParsedInput{Proxies: proxies, Source: "base64"}), nil
			}
		}
	}

	// ④ 纯文本一行或多行 URI
	proxies, err := parseURILines(splitLines(text))
	if err != nil {
		return nil, fmt.Errorf("parse subscription: %w", err)
	}
	return finalize(&ParsedInput{Proxies: proxies, Source: "uri"}), nil
}
