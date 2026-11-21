package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// probeBaseEndpoint proves a WARP base endpoint actually carries traffic.
//
// A dead WireGuard / AWG / MASQUE endpoint still "starts": the userspace tunnel
// comes up with no error, mihomo reports it healthy, WaitReady returns nil. But
// every dial through it dies — so an OpenVPN exit riding on it fails its
// handshake, the connect blames the relay, and the whole candidate list is spent
// on a base that was never going to work. Measured on the user's machine: the
// cached endpoint returned HTTP 502 for every request while the same relay
// carried 572 KB/s in subscription mode.
//
// The check is deliberately cheap: one throwaway core on private ports, one
// short HTTP round-trip. It runs only after a candidate already failed, so a
// healthy connect pays nothing.
func probeBaseEndpoint(ctx context.Context, o options, ce cachedEndpoint, run protoRun) error {
	var buildErr error
	err := withTempCore(ctx, "基础端点自检", func(mixedPort, apiPort int) []byte {
		cfg, e := probeCarrierOnlyConfig(o, ce, run, mixedPort, apiPort)
		if e != nil {
			buildErr = e
		}
		return cfg
	}, func(mixedPort, _ int) error {
		proxyURL, perr := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
		if perr != nil {
			return perr
		}
		client := &http.Client{
			Timeout: 6 * time.Second,
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				DisableKeepAlives: true,
			},
		}
		var last error
		for attempt := 0; attempt < 2; attempt++ {
			resp, rerr := client.Get("http://www.gstatic.com/generate_204")
			if rerr == nil {
				_ = resp.Body.Close()
				// mihomo answers 502 when the outbound dial fails, so a status
				// code is not enough: anything below 400 means bytes moved.
				if resp.StatusCode < 400 {
					return nil
				}
				last = fmt.Errorf("HTTP %d", resp.StatusCode)
			} else {
				last = rerr
			}
		}
		if last == nil {
			last = fmt.Errorf("无响应")
		}
		return fmt.Errorf("基础端点 %s 无法转发数据（%v）", ce.Endpoint, last)
	})
	if buildErr != nil {
		return buildErr
	}
	return err
}
