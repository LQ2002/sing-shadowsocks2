//go:build !linux

package shadowaead_2022

import (
	"syscall"

	N "github.com/sagernet/sing/common/network"
)

// newKeptBatchReader: the buffer-keeping recvmmsg reader is Linux only
// (packet_batch_read_keep_linux.go); elsewhere sing's reader is used.
func newKeptBatchReader(rawConn syscall.RawConn) N.ConnectedPacketBatchReadWaiter {
	return nil
}
