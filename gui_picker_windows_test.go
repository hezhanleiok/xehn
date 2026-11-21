//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestVPNGatePickerTree pins the shape the phone client's picker taught us:
// countries collapse to one row, the expanded country adds an "auto" row and
// its relays in class-then-latency order, and a pinned relay is addressed by
// the slot number the same list shows.
func TestVPNGatePickerTree(t *testing.T) {
	nodes := []vpnGateNode{
		{CountryShort: "JP", CountryLong: "Japan", IP: "198.51.100.1", Port: 443, Proto: "tcp", Profile: "x", Class: "datacenter", PingMS: 88, Score: 30},
		{CountryShort: "JP", CountryLong: "Japan", IP: "198.51.100.2", Port: 443, Proto: "tcp", Profile: "x", Class: "residential", PingMS: 42, Score: 20},
		{CountryShort: "JP", CountryLong: "Japan", IP: "198.51.100.3", Port: 443, Proto: "tcp", Profile: "x", Class: "unknown", LatencyMS: 31, Score: 10},
		{CountryShort: "US", CountryLong: "United States", IP: "198.51.100.4", Port: 443, Proto: "tcp", Profile: "x", Class: "unknown", PingMS: 150, Score: 10},
	}

	u := &natUI{m: &natModel{set: clientSettings{Theme: themeLight}}}
	u.m.vpnNodes = nodes
	u.m.vpnCountries = vpnGateCountries(nodes)
	u.m.vpnExpanded = "JP"

	rows := u.vpnPopupRows()
	wantKinds := []int{vpnRowAuto, vpnRowCountry, vpnRowCountryAuto, vpnRowNode, vpnRowNode, vpnRowNode, vpnRowCountry}
	if len(rows) != len(wantKinds) {
		t.Fatalf("rows = %d, want %d: %+v", len(rows), len(wantKinds), rows)
	}
	for i, want := range wantKinds {
		if rows[i].kind != want {
			t.Fatalf("row %d kind = %d, want %d", i, rows[i].kind, want)
		}
	}
	if rows[1].cc != "JP" || rows[6].cc != "US" {
		t.Fatalf("country order = %q,%q; want JP,US", rows[1].cc, rows[6].cc)
	}

	// Residential first, then the datacenter relay. The old "unknown" cache
	// value folds into residential, and measured latency orders that block.
	wantIPs := []string{"198.51.100.3", "198.51.100.2", "198.51.100.1"}
	for i, want := range wantIPs {
		if got := rows[3+i].node.IP; got != want {
			t.Fatalf("node row %d = %s, want %s", i, got, want)
		}
	}

	slots := map[string]string{
		"198.51.100.3": "JP" + tr("家宽") + "01",
		"198.51.100.2": "JP" + tr("家宽") + "02",
		"198.51.100.1": "JP" + tr("机房") + "01",
	}
	for ip, want := range slots {
		n := rows[3].node
		for _, row := range rows[3:6] {
			if row.node.IP == ip {
				n = row.node
			}
		}
		if got := u.vpnNodeSlot(n); got != want {
			t.Fatalf("slot(%s) = %s, want %s", ip, got, want)
		}
	}

	// 1.0.5: a refresh only reloads the node list, it never TCP-probes, so
	// unpicked nodes show "未检测" instead of a self-reported latency. Only a
	// node the user actually probed carries type · latency · speed.
	for i, row := range rows[3:6] {
		if got := vpnNodeLatencyLabel(row.node); got != tr("未检测") {
			t.Fatalf("row %d latency = %q, want %q", i, got, tr("未检测"))
		}
	}
	probed := rows[3].node
	probed.ProbeState = "ok"
	probed.ProbeMS = 31
	if got := vpnNodeLatencyLabel(probed); !strings.Contains(got, "31ms") {
		t.Fatalf("probed latency label = %q, want 31ms", got)
	}
	if got := vpnCountrySub(u.m.vpnCountries[0]); got != trf("%d 个 · %d 有响应", 3, 1) {
		t.Fatalf("JP sub = %q", got)
	}
	if got := vpnCountrySub(u.m.vpnCountries[1]); got != trf("%d 个", 1) {
		t.Fatalf("US sub = %q", got)
	}

	// The phone client's slot colours: green residential, gold datacenter.
	if got := u.vpnClassColor("residential"); got != rx(27, 127, 59) {
		t.Fatalf("residential colour = %v", got)
	}
	if got := u.vpnClassColor("datacenter"); got != rx(138, 109, 59) {
		t.Fatalf("datacenter colour = %v", got)
	}

	u.m.vpnExpanded = ""
	if rows := u.vpnPopupRows(); len(rows) != 3 {
		t.Fatalf("collapsed rows = %d, want 3", len(rows))
	}
}
