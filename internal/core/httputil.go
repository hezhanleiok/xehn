package core

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// The core's REST API is polled on a 2-second timer while connected
// (Connections for the traffic card, the controller ping for status). Building a
// fresh http.Transport per call leaked one connection pool — and its reader
// goroutine — on every poll, which is the handle and working-set climb users
// report as "memory keeps growing" and the reason the client slowly got slower.
//
// One transport is shared; each call still gets its own timeout by copying the
// lightweight client struct (a copy shares the transport, so the keep-alive pool
// survives between polls and the poll itself gets cheaper).
var (
	apiTransportOnce sync.Once
	apiTransport     *http.Transport
)

func httpClient(timeout time.Duration) *http.Client {
	apiTransportOnce.Do(func() {
		apiTransport = &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		}
	})
	return &http.Client{Timeout: timeout, Transport: apiTransport}
}
