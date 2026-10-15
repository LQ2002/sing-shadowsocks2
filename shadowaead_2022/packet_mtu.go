package shadowaead_2022

import (
	"errors"
	"io"
	"sync/atomic"
	"syscall"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// Oversized datagrams on the client's UDP socket.
//
// sing-box dials the SS2022 server with DF set (IP_PMTUDISC_DO, the
// udp_fragment default), so a sealed datagram larger than the path MTU fails
// with EMSGSIZE instead of being fragmented, and an ICMP "fragmentation
// needed" from the path is queued as a socket error that the next read
// returns as EMSGSIZE (connected UDP socket, __udp4_lib_err). Both used to
// end the copy and so the whole UDP session: on the phone (2026-10-15,
// path MTU 1480 to the test front) every app datagram above ~1386 bytes
// closed its session, and quic-go's PMTU probes (up to 1452 bytes) killed
// HTTP/3 downloads mid-transfer ("no recent network activity").
//
// The packet that does not fit is now dropped and the session goes on, as a
// router drops an oversized DF packet; a QUIC PMTU probe is meant to be
// lost and the sender stays at the size that fits. Keeping DF is deliberate:
// fragments are what made QUIC slow on this chain before (2026-10-07).
//
// After the first EMSGSIZE the socket's path MTU (IP_MTU) gives the largest
// datagram that fits; larger sealed packets are dropped before the send, so
// a batch is not cut short by one of them. The kernel's PMTU entry expires
// (10 minutes by default) and may grow, so a cached limit older than
// pathMTURecheck is queried again before it drops anything.

const pathMTURecheck = 30 * time.Second

type pathMTULimit struct {
	limit   atomic.Int32 // largest UDP payload that fits, 0 = unknown
	checked atomic.Int64 // when limit was queried (UnixNano)
}

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

// refreshPathMTU queries the socket's path MTU after an EMSGSIZE.
func (c *clientPacketConn) refreshPathMTU() {
	limit := 0
	if writer, isWriter := c.AbstractConn.(io.Writer); isWriter {
		if _, rawConn := N.SyscallConnForWrite(writer); rawConn != nil {
			limit = socketMaxDatagram(rawConn)
		}
	}
	c.pathMTU.limit.Store(int32(limit))
	c.pathMTU.checked.Store(time.Now().UnixNano())
}

// tooBig reports whether a sealed datagram of size bytes is known not to
// fit the path.
func (c *clientPacketConn) tooBig(size int) bool {
	limit := int(c.pathMTU.limit.Load())
	if limit == 0 || size <= limit {
		return false
	}
	if time.Now().UnixNano()-c.pathMTU.checked.Load() > int64(pathMTURecheck) {
		c.refreshPathMTU()
		limit = int(c.pathMTU.limit.Load())
		if limit == 0 || size <= limit {
			return false
		}
	}
	return true
}
