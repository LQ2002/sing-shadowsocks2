//go:build !linux

package shadowaead_2022

import (
	"syscall"

	N "github.com/sagernet/sing/common/network"
)

// UDP_GRO exists only on Linux; see packet_batch_read_gro_linux.go.

type groState struct{}

func (s *groState) leave() {}

func newGROBatchReader(conn *clientPacketConn, rawConn syscall.RawConn, options N.ReadWaitOptions) N.ConnectedPacketBatchReadWaiter {
	return nil
}
