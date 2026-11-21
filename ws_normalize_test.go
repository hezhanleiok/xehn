package main

import "testing"

func TestVLESSWSURLNormalized(t *testing.T) {
	link := "vless://e7674561-e4ad-4f95-9e4a-6615f8842ac9@guessable-turnpikes.cdn-content.com:443?type=ws&security=tls&path=%2Fws&host=guessable-turnpikes.cdn-content.com&sni=guessable-turnpikes.cdn-content.com&fp=chrome#Kansas%20City%20via%20CDN%201"
	parsed, err := parseSubscription([]byte(link), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Proxies) == 0 {
		t.Fatal("no proxy")
	}
	p := parsed.Proxies[0]
	for k, v := range p.Fields {
		t.Logf("%s = %#v", k, v)
	}
	if _, ok := p.Fields["path"]; ok {
		t.Error("flat `path` survived; mihomo will ignore it")
	}
	if _, ok := p.Fields["host"]; ok {
		t.Error("flat `host` survived; mihomo will ignore it")
	}
	opts, ok := p.Fields["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("ws-opts missing: %#v", p.Fields["ws-opts"])
	}
	if opts["path"] != "/ws" {
		t.Errorf("ws-opts.path = %#v", opts["path"])
	}
	h, _ := opts["headers"].(map[string]any)
	if h["Host"] != "guessable-turnpikes.cdn-content.com" {
		t.Errorf("ws-opts.headers.Host = %#v", h["Host"])
	}
}
