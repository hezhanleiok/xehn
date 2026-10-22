package warp

// 这份测试把手机端的分类规则与电脑版 stageJ 的结论对拍。
//
// 目的：手机端只拿得到 ip-api（isp/org/as/mobile/proxy/hosting），没有
// proxycheck / PeeringDB / PTR；必须证明「少了这些证据，分类不会系统性跑偏」。
// 电脑版的 classify.js 用的是全量证据，它的 classification.json 就是基准。
//
// 默认跳过；对拍时：
//
//	$env:PC_STAGE_DIR='E:/XEHN/.research/stageJ'; go test -run PC -v ./warp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type pcEvidenceFile struct {
	Rows []struct {
		Tag    string `json:"tag"`
		IP     string `json:"ip"`
		ASN    int    `json:"asn"`
		ASName string `json:"as_name"`
		PTR    string `json:"ptr"`
		Ipapi  struct {
			Status  string `json:"status"`
			ISP     string `json:"isp"`
			Org     string `json:"org"`
			AS      string `json:"as"`
			Mobile  bool   `json:"mobile"`
			Proxy   bool   `json:"proxy"`
			Hosting bool   `json:"hosting"`
		} `json:"ipapi"`
	} `json:"rows"`
}

type pcClassificationFile struct {
	Rows []struct {
		Tag            string `json:"tag"`
		Classification struct {
			Label string `json:"label"`
		} `json:"classification"`
	} `json:"rows"`
}

func TestCompareWithPCCLassification(t *testing.T) {
	dir := os.Getenv("PC_STAGE_DIR")
	if dir == "" {
		t.Skip("未设置 PC_STAGE_DIR")
	}
	var ev pcEvidenceFile
	raw, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatalf("读 evidence.json: %v", err)
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("解析 evidence.json: %v", err)
	}
	var cls pcClassificationFile
	raw, err = os.ReadFile(filepath.Join(dir, "classification.json"))
	if err != nil {
		t.Fatalf("读 classification.json: %v", err)
	}
	if err := json.Unmarshal(raw, &cls); err != nil {
		t.Fatalf("解析 classification.json: %v", err)
	}
	want := map[string]string{}
	for _, r := range cls.Rows {
		want[r.Tag] = r.Classification.Label
	}

	var agree, compare, falseResidential, falseDatacenter int
	for _, r := range ev.Rows {
		pc, ok := want[r.Tag]
		if !ok || r.Ipapi.Status != "success" {
			continue
		}
		compare++
		n := VPNGateNode{Host: r.Tag, IP: r.IP}
		enrichClassify(&n, ipAPIResult{
			Status:  "success",
			ISP:     r.Ipapi.ISP,
			Org:     r.Ipapi.Org,
			AS:      r.Ipapi.AS,
			Mobile:  r.Ipapi.Mobile,
			Proxy:   r.Ipapi.Proxy,
			Hosting: r.Ipapi.Hosting,
		})
		// 电脑版的 UNCERTAIN 在手机端就是「未知」，两边语义一致；
		// 它的标签是大写，统一成小写再比。
		got := n.Class
		pcNorm := strings.ToLower(pc)
		if pcNorm == "uncertain" {
			pcNorm = "unknown"
		}
		if got == pcNorm {
			agree++
			continue
		}
		if got == "residential" && pcNorm == "datacenter" {
			falseResidential++
		}
		if got == "datacenter" && pcNorm == "residential" {
			falseDatacenter++
		}
		t.Logf("不一致 %-18s pc=%-11s ours=%-11s isp=%q as=%q hosting=%v",
			r.Tag, pcNorm, got, r.Ipapi.ISP, r.Ipapi.AS, r.Ipapi.Hosting)
	}
	t.Logf("对拍 %d 个节点：一致 %d，把机房判成家宽 %d，把家宽判成机房 %d",
		compare, agree, falseResidential, falseDatacenter)
	if compare == 0 {
		t.Fatal("没有可比对的样本")
	}
	// 安全底线：宁可「未知」，也不能把机房标成家宽（这个标记会直接引导用户选节点）。
	if falseResidential > 0 {
		t.Errorf("有 %d 个节点被误标为家宽（电脑版判为机房）", falseResidential)
	}
}
