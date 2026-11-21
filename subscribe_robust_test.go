//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestParseSubscriptionSurvivesGarbage pins the entry point's safety: the input
// is whatever a subscription server (or a hostile proxy) returns, and a panic
// here would unwind a worker goroutine and take the process with it. Every case
// must either parse or return an error — never panic.
func TestParseSubscriptionSurvivesGarbage(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"whitespace":       "   \n\t\n",
		"plain text":       "this is not a subscription at all",
		"html error page":  "<html><body>502 Bad Gateway</body></html>",
		"json object":      `{"proxies": "not an array"}`,
		"json null":        `null`,
		"truncated yaml":   "proxies:\n  - name: \"a\"\n    type: ss\n    server: ",
		"proxies not list": "proxies: 42\n",
		"empty proxies":    "proxies: []\n",
		"null proxy item":  "proxies:\n  - null\n  - name: ok\n    type: ss\n    server: 1.2.3.4\n    port: 1\n",
		"port as string":   "proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: \"443\"\n",
		"deep nesting":     strings.Repeat("- ", 5000) + "x",
		"binary junk":      string([]byte{0x00, 0xff, 0xfe, 0x01, 0x02, 0x7f}),
		"base64 junk":      "c3M6Ly9ub3QtcmVhbGx5",
		"yaml bomb anchor": "a: &x [*x]\nproxies: []\n",
		"only comments":    "# nothing here\n# really\n",
	}
	for name, in := range cases {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("%s: parser panicked: %v", name, rec)
				}
			}()
			res, err := ParseSubscription([]byte(in))
			if err == nil && res == nil {
				t.Fatalf("%s: nil result with nil error", name)
			}
			if res != nil && len(res.Proxies) > 0 {
				// Any node that survives must at least carry a name and type.
				for _, p := range res.Proxies {
					if p.Name == "" || p.Type == "" {
						t.Fatalf("%s: accepted a nameless/typeless node: %+v", name, p)
					}
				}
			}
		}()
	}
}

// TestParseSubscriptionRejectsOversizedInput pins the size guard: a 4MB cap
// keeps a hostile or broken server from allocating without limit.
func TestParseSubscriptionRejectsOversizedInput(t *testing.T) {
	huge := make([]byte, maxSubscriptionBytes+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	if _, err := ParseSubscription(huge); err == nil {
		t.Fatal("oversized input was accepted")
	}
}
