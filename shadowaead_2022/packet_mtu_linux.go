//go:build linux

package shadowaead_2022

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// socketMaxDatagram returns the largest UDP payload the connected socket's
// path MTU allows, or 0 when it cannot be read.
func socketMaxDatagram(rawConn syscall.RawConn) int {
	var limit int
	_ = rawConn.Control(func(fd uintptr) {
		if mtu, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU); err == nil && mtu > 28 {
			limit = mtu - 20 - 8
			return
		}
		if mtu, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU); err == nil && mtu > 48 {
			limit = mtu - 40 - 8
		}
	})
	return limit
}
