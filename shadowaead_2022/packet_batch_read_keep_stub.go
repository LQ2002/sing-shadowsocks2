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

// newGROBatchReader: the UDP_GRO reader is Linux only
// (packet_batch_read_gro_linux.go).
func newGROBatchReader(rawConn syscall.RawConn) N.ConnectedPacketBatchReadWaiter {
	return nil
}

// newUringBatchReader: the io_uring reader is Linux only
// (packet_batch_read_uring_linux.go).
func newUringBatchReader(rawConn syscall.RawConn) (N.ConnectedPacketBatchReadWaiter, func()) {
	return nil, nil
}

// uringConnectedWriter: the io_uring writer is Linux only
// (packet_batch_write_uring_linux.go).
type uringConnectedWriter struct{ N.ConnectedPacketBatchWriter }

func (w *uringConnectedWriter) Close() {}

func newUringConnectedWriter(rawConn syscall.RawConn, noGSO bool) *uringConnectedWriter {
	return nil
}

func gsoDisabled(conn any) bool { return false }
