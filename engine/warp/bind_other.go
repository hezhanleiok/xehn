//go:build !linux

package warp

import "syscall"

const deviceBindSupported = false

func deviceControl(string, int) func(network, address string, c syscall.RawConn) error { return nil }
