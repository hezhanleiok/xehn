package warp

// VPN Gate 节点列表（OpenVPN 出口的候选池）。
//
// 数据源与电脑版一致：https://www.vpngate.net/api/iphone/ 的 CSV，15 列：
//
//	#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,
//	Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
//
// 两个必须知道的现实（都来自电脑版审计）：
//  1. vpngate.net 在受限网络里直连会被拦，所以抓取要能走 WARP 隧道；
//  2. CSV 里的 Ping/Speed 是节点自报值，未经实测，不能当可用性证据。
//
// 所以这里做三件事：抓列表 → 实测 TCP 延迟 → 按 ip-api 的 ASN/ISP 证据分类
// （家宽/机房/未知）。分类规则移植自电脑版的 stageJ/classify.js，只少了 PTR
// 证据（ip-api 不返回 PTR），未知比例会略高，但不会把机房当住宅。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// vpnGateAPI 是 VPN Gate 的公开节点接口。HTTPS 优先，明文只作回退。
const vpnGateAPI = "https://www.vpngate.net/api/iphone/"

// vpnGateMaxNodes 是单次最多保留的节点数。接口通常给 60–120 条，全留；
// 上限只是防止某天接口返回异常大的列表把内存/APK 私有目录撑爆。
const vpnGateMaxNodes = 200

// VPNGateNode 是一个候选节点。
//
// Config 是 .ovpn 原文（含内联证书），体积约 13 KB，**不进** 给 UI 的 JSON：
// 列表只给元数据，真正连接时再按 ID 取配置（见 VPNGateNodeConfig）。
type VPNGateNode struct {
	ID string `json:"id"`
	// Host 是 VPN Gate 的 HostName（如 public-vpn-153），常用于判断是不是
	// VPN Gate 作者自己的机房 VPS。
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	CC       string `json:"cc"`
	Country  string `json:"country"`
	Operator string `json:"operator"`
	// PingMS/SpeedBps 是节点自报值，仅作展示参考（见文件头）。
	PingMS   int `json:"pingMS"`
	SpeedBps int `json:"speedBps"`
	Sessions int `json:"sessions"`
	// LatencyMS 是实测 TCP 握手耗时；0 = 未测（UDP 节点或探测失败）。
	LatencyMS int `json:"latencyMS"`
	// Class 是分类结果：residential / datacenter / unknown。
	Class string `json:"class"`
	// ClassSource 说明这个分类是怎么来的：host / ipapi / none。
	ClassSource string `json:"classSource"`
	// Shared 表示 ip-api 把它标成了 proxy/VPN（电脑版审计里 6/6 家宽节点
	// 都命中 PacketStream 共享代理，所以这个标记要展示，但不能据此隐藏节点）。
	Shared bool `json:"shared"`
	// ISP/AS 是分类依据，也一并给 UI（用户想看"为什么是家宽"）。
	ISP string `json:"isp"`
	AS  string `json:"as"`

	Config string `json:"-"`
}

// VPNGateCache 是落盘结构：比给 UI 的多一个抓取时间与配置原文。
type VPNGateCache struct {
	FetchedAt int64         `json:"fetchedAt"`
	Nodes     []VPNGateNode `json:"nodes"`
}

// NodesJSON 返回给 UI 的列表（不含配置原文）。
func (c *VPNGateCache) NodesJSON() string {
	if c == nil {
		return `{"fetchedAt":0,"nodes":[]}`
	}
	b, err := json.Marshal(c)
	if err != nil {
		return `{"fetchedAt":0,"nodes":[]}`
	}
	return string(b)
}

// ParseVPNGateCSV 解析接口返回的 CSV。
//
// 用 encoding/csv 而不是 strings.Split：CountryLong 里出现过带逗号的名字，
// 直接切会把后 14 列全部错位。
func ParseVPNGateCSV(text string) []VPNGateNode {
	// 去掉开头的 "*" 注释行（接口会返回 "* | *" 之类的提示）。
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "*") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	r := csv.NewReader(strings.NewReader(b.String()))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	out := make([]VPNGateNode, 0, 128)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 15 {
			continue
		}
		if strings.HasPrefix(rec[0], "#") || strings.EqualFold(rec[1], "IP") {
			continue
		}
		n := VPNGateNode{
			Host:     strings.TrimSpace(rec[0]),
			IP:       strings.TrimSpace(rec[1]),
			Country:  strings.TrimSpace(rec[5]),
			CC:       strings.ToUpper(strings.TrimSpace(rec[6])),
			Operator: strings.TrimSpace(rec[12]),
		}
		n.PingMS, _ = strconv.Atoi(strings.TrimSpace(rec[3]))
		n.SpeedBps, _ = strconv.Atoi(strings.TrimSpace(rec[4]))
		n.Sessions, _ = strconv.Atoi(strings.TrimSpace(rec[7]))

		raw := strings.TrimSpace(rec[14])
		if raw == "" {
			continue
		}
		cfg, derr := base64.StdEncoding.DecodeString(raw)
		if derr != nil {
			continue
		}
		oc, perr := ParseOpenVPNConfig(string(cfg))
		if perr != nil {
			continue
		}
		n.Config = string(cfg)
		n.Port = oc.RemotePort
		n.Proto = oc.Proto
		if oc.RemoteHost != "" && net.ParseIP(oc.RemoteHost) != nil {
			// 配置里的 remote 才是真实的落地地址；CSV 的 IP 列偶尔与它不一致。
			n.IP = oc.RemoteHost
		}
		if n.IP == "" || n.Port <= 0 {
			continue
		}
		n.ID = strings.ToLower(fmt.Sprintf("%s-%s-%d", n.CC, n.IP, n.Port))
		n.Class, n.ClassSource, n.Shared, n.ISP, n.AS = classifyVPNGate(n)
		out = append(out, n)
		if len(out) >= vpnGateMaxNodes {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LatencyMS != out[j].LatencyMS {
			return out[i].LatencyMS < out[j].LatencyMS
		}
		return out[i].SpeedBps > out[j].SpeedBps
	})
	return out
}

// ---- 分类 ----

// hardDCASN 是电脑版 classify.js 里的硬机房 ASN 表，逐字移植。
var hardDCASN = map[int]bool{
	16509: true, 14618: true, 15169: true, 396982: true, 8075: true,
	13335: true, 14061: true, 20473: true, 63949: true, 16276: true,
	24940: true, 51167: true, 9009: true, 36352: true, 53667: true,
	29802: true, 40676: true, 46844: true, 62240: true,
}

// residentialBrands 是电脑版 BRANDS 表里与 VPN Gate 实际节点相关的品牌。
// 正则统一在 Go 侧预编译；命中即视为住宅接入的强证据之一。
var residentialBrands = []string{
	"korea telecom", "kt corporation", "sk broadband", "skb-as-kr", "lg u+", "lgu+", "lg uplus",
	"softbank", "kddi", "comcast", "charter", "spectrum", "frontier", "fidium",
	"consolidated communications", "so-net", "sony network communications", "jcom",
	"chubu telecommunications", "commufa", "ctcx", "asahi net", "asahi-net", "ocn",
	"ntt-me", "wakwak", "xephion", "rostelecom", "er-telecom", "wave broadband",
	"cable & wireless panama", "lg powercomm", "powervis", "lg hellovision",
	"hellovision", "cjckn", "cmb kwangju", "biglobe", "plala", "nifty", "@nifty",
	// 补充：电脑版对拍中出现的住宅运营商，品牌本身就是强证据。
	"orange", "etisalat", "arteria", "hawaiian telcom", "tt dotcom", "ttnet",
}

var dcKeywords = []string{
	"hosting", "cloud", "server", "datacenter", "data center", "data-centre", "colocation",
	" vps", "vps ", "dedicated", " idc", "amazon", "google llc", "microsoft", "oracle",
	"digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo", "alibaba", "tencent",
	"cloudflare", "choopa", "leaseweb", "m247", "psychz", "quadranet", "colocrossing",
}

var accessKeywords = []string{
	"telecom", "communications", "broadband", "cable", "fiber", "fibre", " dsl", " isp",
}

// classifyVPNGate 给出 家宽/机房/未知。
//
// 规则顺序与电脑版 classify.js 一致：硬机房 ASN 直接判机房；机房证据 ≥2 组判
// 机房；机房与住宅证据冲突判未知；否则按住宅证据判定。**宁可未知，不把机房
// 说成家宽** —— 这个标记会直接影响用户选节点。
func classifyVPNGate(n VPNGateNode) (class, source string, shared bool, isp, asn string) {
	// ① 离线先验：VPN Gate 自己的 public-vpn-* 全部是作者的机房 VPS
	//    （电脑版 CFnew 也是用这个前缀排除的）。
	if strings.HasPrefix(strings.ToLower(n.Host), "public-vpn") {
		return "datacenter", "host", false, "VPN Gate public relay", ""
	}
	return "unknown", "none", false, "", ""
}

// enrichClassify 用 ip-api 的批量结果补全分类。
//
// 只在拿到真实 isp/org/as 时覆盖 offline 结论；拿不到就保持 unknown，
// 不用猜测填空。
func enrichClassify(n *VPNGateNode, r ipAPIResult) {
	if r.Status != "success" {
		return
	}
	n.ISP = strings.TrimSpace(r.ISP)
	n.AS = strings.TrimSpace(r.AS)
	if n.ISP == "" {
		n.ISP = strings.TrimSpace(r.Org)
	}
	n.Shared = r.Proxy

	blob := strings.ToLower(n.ISP + " " + r.Org + " " + r.AS)
	dcGroups := 0
	if r.Hosting {
		dcGroups++
	}
	if containsAny(blob, dcKeywords) {
		dcGroups++
	}
	if asn := parseASN(r.AS); asn > 0 && hardDCASN[asn] {
		n.Class, n.ClassSource, n.Shared = "datacenter", "ipapi", r.Proxy
		return
	}

	// 住宅信号只认「消费级品牌」与移动网络两类强证据。
	//
	// 为什么不像电脑版那样把 access-type 关键词（telecom / communications /
	// broadband / cable）也算一组：我们拿不到 PTR 与 PeeringDB，只有 ip-api。
	// 用 26 个电脑版已判定样本对拍时，"Cogent Communications"、"NTT
	// Communications"、"FPT Telecom" 这类运营商/骨干网会被 access 关键词误标成
	// 家宽，而电脑版判的是「不确定」。宁可显示未知，也不能把商业线路说成家宽。
	brandHit := containsAny(blob, residentialBrands)
	residential := brandHit || r.Mobile
	if dcGroups >= 2 || (dcGroups >= 1 && !residential) {
		n.Class, n.ClassSource = "datacenter", "ipapi"
		return
	}
	if dcGroups >= 1 && residential {
		n.Class, n.ClassSource = "unknown", "ipapi"
		return
	}
	if residential {
		n.Class, n.ClassSource = "residential", "ipapi"
		return
	}
	n.Class, n.ClassSource = "unknown", "ipapi"
}

func parseASN(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	if !strings.HasPrefix(s, "AS") {
		return 0
	}
	s = s[2:]
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	v, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return v
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// ---- ip-api 批量补证 ----

const ipAPIEndpoint = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,mobile,proxy,hosting,query"

type ipAPIResult struct {
	Status  string `json:"status"`
	Query   string `json:"query"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Mobile  bool   `json:"mobile"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
}

// enrichWithIPAPI 一次批量查询最多 100 个 IP（免费接口的上限）。
//
// 失败不影响列表可用性：分类退回 offline 先验（多数是 unknown），
// 由调用方在日志里说明「本次没有补证」。
func enrichWithIPAPI(ctx context.Context, client *http.Client, nodes []VPNGateNode) (int, error) {
	// 同一 IP 只查一次（一个国家多个端口很常见）。
	uniq := make([]string, 0, 128)
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.IP == "" || seen[n.IP] {
			continue
		}
		seen[n.IP] = true
		uniq = append(uniq, n.IP)
	}
	if len(uniq) == 0 {
		return 0, nil
	}

	byIP := map[string]ipAPIResult{}
	for start := 0; start < len(uniq); start += 100 {
		end := start + 100
		if end > len(uniq) {
			end = len(uniq)
		}
		payload, err := json.Marshal(uniq[start:end])
		if err != nil {
			return 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ipAPIEndpoint, bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return len(byIP), err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return len(byIP), fmt.Errorf("ip-api HTTP %d", resp.StatusCode)
		}
		var rows []ipAPIResult
		if err := json.Unmarshal(body, &rows); err != nil {
			return len(byIP), err
		}
		for _, r := range rows {
			if r.Query != "" {
				byIP[r.Query] = r
			}
		}
	}
	for i := range nodes {
		if r, ok := byIP[nodes[i].IP]; ok {
			enrichClassify(&nodes[i], r)
		}
	}
	return len(byIP), nil
}

// ---- 抓取 ----

// VPNGateFetchOptions 是抓取一轮的输入。
type VPNGateFetchOptions struct {
	UnderlayProto    string
	UnderlayEndpoint string
	UnderlayPrefer   string
	IPv6             bool
	Timeout          time.Duration
	HandshakeTimeout time.Duration
	// Report 逐条写进度（App 日志面板）。
	Report func(string)
}

func (o *VPNGateFetchOptions) report(msg string) {
	if o.Report != nil {
		o.Report(msg)
	}
}

// FetchVPNGate 抓一轮：直连优先 → 失败则起一条临时 WARP netstack 再抓。
//
// 走 WARP 的原因与电脑版一致：vpngate.net 在受限网络里直连 8s 超时，
// 而经 WARP 是 200。临时隧道只用于抓取/补证/测延迟，抓完立刻关掉，
// 不建立系统 VPN，也不影响当前会话。
func FetchVPNGate(ctx context.Context, o VPNGateFetchOptions) ([]VPNGateNode, error) {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}

	text, sess, err := fetchVPNGateTextWithFallback(ctx, o)
	if sess != nil {
		defer sess.Close()
	}
	if err != nil {
		return nil, err
	}

	nodes := ParseVPNGateCSV(text)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("VPN Gate 返回了 %d 字节，但没有解析出任何可用节点", len(text))
	}
	o.report(fmt.Sprintf("VPN Gate 节点 %d 个（%d 个国家）", len(nodes), countCountries(nodes)))

	stack := (*ipStack)(nil)
	if sess != nil {
		stack = sess.tn.stack()
	}

	// ip-api 补证：一次批量请求拿到 ASN/ISP/机房标记，分类才不是靠猜。
	enrichCtx, enrichCancel := context.WithTimeout(ctx, 20*time.Second)
	client := &http.Client{Timeout: 15 * time.Second}
	if stack != nil {
		client = newStackHTTPClient(stack, 15*time.Second)
	}
	n, err := enrichWithIPAPI(enrichCtx, client, nodes)
	enrichCancel()
	if err != nil {
		o.report(fmt.Sprintf("节点分类补证只完成 %d 个（%v）；其余保持“未知”", n, err))
	} else {
		o.report(fmt.Sprintf("节点分类补证完成 %d 个 IP", n))
	}

	// 实测 TCP 延迟（只对 tcp 节点；udp 节点保留自报 ping）。
	probeLatency(ctx, stack, nodes, 8)
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		// 有实测用实测；没有实测的排在后面，而不是拿自报 ping 冒充。
		if (a.LatencyMS > 0) != (b.LatencyMS > 0) {
			return a.LatencyMS > 0
		}
		if a.LatencyMS != b.LatencyMS {
			return a.LatencyMS < b.LatencyMS
		}
		return a.SpeedBps > b.SpeedBps
	})
	return nodes, nil
}

// fetchVPNGateTextWithFallback 返回 CSV 与（可能为 nil 的）临时隧道。
func fetchVPNGateTextWithFallback(ctx context.Context, o VPNGateFetchOptions) (string, *Session, error) {
	// 直连只给 8 秒：受限网络里这个域名必然超时，等满 20 秒才转 WARP 纯属白等。
	direct := o
	if direct.Timeout > 8*time.Second {
		direct.Timeout = 8 * time.Second
	}
	text, err := fetchVPNGateText(ctx, nil, direct)
	if err == nil {
		return text, nil, nil
	}
	o.report("直连抓取 VPN Gate 失败（" + shortErr(err) + "），改走 WARP…")
	sess, derr := dialFetchUnderlay(ctx, o)
	if derr != nil {
		return "", nil, fmt.Errorf("抓取 VPN Gate 失败：直连 %v；WARP %v", err, derr)
	}
	text, err = fetchVPNGateText(ctx, sess.tn.stack(), o)
	if err != nil {
		sess.Close()
		return "", nil, fmt.Errorf("经 WARP 抓取 VPN Gate 失败: %w", err)
	}
	return text, sess, nil
}

// dialFetchUnderlay 起一条只用于抓取的 WARP netstack 会话（tunFD=0）。
func dialFetchUnderlay(ctx context.Context, o VPNGateFetchOptions) (*Session, error) {
	saved := tunFD
	tunFD = 0
	handshake := o.HandshakeTimeout
	if handshake <= 0 {
		handshake = 3 * time.Second
	}
	sess, err := Dial(ctx, Options{
		Proto:            o.UnderlayProto,
		Endpoint:         o.UnderlayEndpoint,
		Prefer:           o.UnderlayPrefer,
		IPv6:             o.IPv6,
		Sample:           2,
		HandshakeTimeout: handshake,
		VerifyTimeout:    8 * time.Second,
		Budget:           60 * time.Second,
		NoHedge:          true,
		Report:           o.Report,
	})
	tunFD = saved
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// fetchVPNGateText 抓 CSV 原文。stack 非 nil 时所有连接都走隧道 netstack。
func fetchVPNGateText(ctx context.Context, stack *ipStack, o VPNGateFetchOptions) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	client := &http.Client{Timeout: o.Timeout}
	if stack != nil {
		client = newStackHTTPClient(stack, o.Timeout)
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, vpnGateAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "xiaohe-vpn-android")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// newStackHTTPClient 是一个「DNS 与连接都在隧道里」的 HTTP 客户端。
//
// 不能直接复用 ipStack.client：那个把目标写死成 Cloudflare /meta。
func newStackHTTPClient(stack *ipStack, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if a, perr := netip.ParseAddr(host); perr == nil {
				return stack.tnet.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
			}
			ips, lerr := stack.tnet.LookupContextHost(ctx, host)
			if lerr != nil || len(ips) == 0 {
				return nil, fmt.Errorf("隧道内解析 %s 失败: %v", host, lerr)
			}
			return stack.tnet.DialContext(ctx, "tcp", net.JoinHostPort(preferV4(ips), port))
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// probeLatency 实测每个节点端口的 TCP 握手耗时。
//
// 只测 proto=tcp 的节点：UDP 节点用 TCP 探测得到的是「端口没开」，
// 不是延迟，写成延迟会误导用户。UDP 节点保留 CSV 的自报 Ping（并标注）。
func probeLatency(ctx context.Context, stack *ipStack, nodes []VPNGateNode, concurrency int) {
	if len(nodes) == 0 {
		return
	}
	if concurrency <= 0 {
		concurrency = 8
	}
	dial := func(c context.Context, addr string) (net.Conn, error) {
		if stack != nil {
			return stack.tnet.DialContext(c, "tcp", addr)
		}
		var d net.Dialer
		return d.DialContext(c, "tcp", addr)
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range nodes {
		if nodes[i].Proto != "tcp" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(n *VPNGateNode) {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			start := time.Now()
			conn, err := dial(c, net.JoinHostPort(n.IP, strconv.Itoa(n.Port)))
			if err != nil {
				return
			}
			_ = conn.Close()
			n.LatencyMS = int(time.Since(start).Milliseconds())
		}(&nodes[i])
	}
	wg.Wait()
}

func countCountries(nodes []VPNGateNode) int {
	m := map[string]bool{}
	for _, n := range nodes {
		m[n.CC] = true
	}
	return len(m)
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// ---- 缓存 ----

// vpnGateConfigsPath 是配置原文的 sidecar 文件（与列表同目录）。
//
// 为什么不塞进列表那个 JSON：列表每次打开设置页都要整份搬到 Kotlin
// （VPNGateNodesJSON），而一份 .ovpn 约 13 KB、上百个节点就是 1.3 MB ——
// 这些字节对界面毫无用处。列表保持小，配置原文单独落一份。
func vpnGateConfigsPath(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), "vpn-gate-configs.json")
}

// writeFileAtomic 先写临时文件再改名，避免半截 JSON 被当成缓存。
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadVPNGateCache 读磁盘缓存；不存在/损坏返回 nil（调用方按“没有缓存”处理）。
func LoadVPNGateCache(path string) *VPNGateCache {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c VPNGateCache
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	// 配置原文在 sidecar 里。读不到只意味着「眼下没有能连的 OpenVPN 节点」，
	// 不该连累节点列表一起消失。
	if cb, cerr := os.ReadFile(vpnGateConfigsPath(path)); cerr == nil {
		var cfgs map[string]string
		if json.Unmarshal(cb, &cfgs) == nil {
			for i := range c.Nodes {
				if cfg, ok := cfgs[c.Nodes[i].ID]; ok {
					c.Nodes[i].Config = cfg
				}
			}
		}
	}
	return &c
}

// SaveVPNGateCache 落盘：列表 + 配置原文两份（都是原子写）。
func SaveVPNGateCache(path string, c *VPNGateCache) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, b); err != nil {
		return err
	}
	// 配置原文必须一起落盘：只存列表的后果是「进程重启后每个节点都变成
	// 没有配置」，界面看着一切正常，连接却只能退回普通隧道（真机踩过）。
	cfgs := make(map[string]string, len(c.Nodes))
	for _, n := range c.Nodes {
		if n.Config != "" {
			cfgs[n.ID] = n.Config
		}
	}
	if len(cfgs) == 0 {
		return nil
	}
	cb, err := json.Marshal(cfgs)
	if err != nil {
		return err
	}
	return writeFileAtomic(vpnGateConfigsPath(path), cb)
}
