package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Share-link fp is the uTLS ClientHello fingerprint (chrome, firefox, …), which
// mihomo carries in client-fingerprint. It used to be mapped to fingerprint —
// the certificate SPKI pin — so a URI import dropped the uTLS fingerprint and
// the CDN-fronted TLS handshake failed (an A/B on a real subscription measured
// 19/46 nodes alive with client-fingerprint vs 10/46 with fingerprint). These
// lock the mapping down for both the query-string and the vmess JSON forms.

func TestShareLinkFPMapsToClientFingerprint(t *testing.T) {
	vless := "vless://892b7269-a6cc-4770-98be-d9a756f6b280@cf.example.com:443" +
		"?encryption=none&security=tls&sni=backend.example.com&fp=chrome" +
		"&type=ws&host=backend.example.com&path=%2F%3Fed%3D2048#uri-node"
	parsed, err := ParseSubscription([]byte(vless))
	if err != nil {
		t.Fatalf("ParseSubscription(vless): %v", err)
	}
	if len(parsed.Proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(parsed.Proxies))
	}
	f := parsed.Proxies[0].Fields
	if f["client-fingerprint"] != "chrome" {
		t.Errorf("client-fingerprint = %v, want chrome (fp must map here)", f["client-fingerprint"])
	}
	if _, ok := f["fingerprint"]; ok {
		t.Errorf("fingerprint = %v; fp must NOT land in the certificate-pin field", f["fingerprint"])
	}
}

func TestVmessJSONFPMapsToClientFingerprint(t *testing.T) {
	blob := map[string]any{
		"v": "2", "ps": "vmess-node", "add": "cf.example.com", "port": "443",
		"id": "892b7269-a6cc-4770-98be-d9a756f6b280", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "backend.example.com", "path": "/?ed=2048",
		"tls": "tls", "sni": "backend.example.com", "fp": "chrome",
	}
	raw, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	uri := "vmess://" + base64.StdEncoding.EncodeToString(raw)
	parsed, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("ParseSubscription(vmess): %v", err)
	}
	if len(parsed.Proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(parsed.Proxies))
	}
	f := parsed.Proxies[0].Fields
	if f["client-fingerprint"] != "chrome" {
		t.Errorf("client-fingerprint = %v, want chrome (vmess fp must map here)", f["client-fingerprint"])
	}
	if _, ok := f["fingerprint"]; ok {
		t.Errorf("fingerprint = %v; vmess fp must NOT land in the certificate-pin field", f["fingerprint"])
	}
}