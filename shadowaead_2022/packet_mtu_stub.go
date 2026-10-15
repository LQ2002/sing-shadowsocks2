//go:build !linux

package shadowaead_2022

import "syscall"

// socketMaxDatagram: the path MTU query is Linux only; elsewhere an
// oversized datagram is still dropped on EMSGSIZE, just not filtered ahead.
func socketMaxDatagram(rawConn syscall.RawConn) int {
	return 0
}
