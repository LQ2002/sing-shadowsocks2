package shadowaead_2022

import (
	"io"
	"os"
	"syscall"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Download batching for the client side of SIP022 UDP, the read-side twin of
// packet_batch.go.
//
// Without it a packet copy out of this conn reads one datagram per recvfrom
// and hands each to the destination on its own. With a batch read waiter,
// sing's copy loop (bufio copyPacketBatchWaitWithPool) takes every datagram
// already queued on the connected UDP socket in one recvmmsg, opens each one
// here exactly as readPacket does, and passes the whole batch to a batch
// writer in the same goroutine. In sing-box's eBPF inbound that writer sends
// them to the app with sendmmsg/GSO, so no hand-off between goroutines (and no
// futex wakeup) is needed per batch: on the daily phone (2026-10-13, HTTP/3
// download) those hand-offs were ~9% of sing-box CPU and the per-datagram
// reads ~11%.
//
// The datagrams on the wire are unchanged. Packets are opened in arrival
// order on one goroutine, so the replay window sees the same sequence as with
// single reads. A datagram that fails to open (bad tag, replayed packet ID,
// unknown header) is dropped from the batch; the batch only fails when no
// datagram in it could be opened, which for a batch of one is the old
// behaviour.
//
// The waiter exists only when the client's reader exposes the connected
// socket with nothing in between that must see the reads
// (N.SyscallConnForRead returns no SyscallReader). Otherwise copies keep
// using the single-packet read waiter.
//
// SS2_DISABLE_UDP_BATCH_READ=1 turns it off (for A/B tests).
//
// On Linux the first batch read also switches the socket to UDP_GRO, so the
// datagrams the network already coalesced arrive whole and are split here
// (packet_batch_read_gro_linux.go, SS2_DISABLE_UDP_GRO=1 to keep it off).

var disableUDPBatchRead = os.Getenv("SS2_DISABLE_UDP_BATCH_READ") == "1"

var _ N.PacketBatchReadWaitCreator = (*clientPacketConn)(nil)

func (c *clientPacketConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	if disableUDPBatchRead {
		return nil, false
	}
	socketReader := &clientSocketReader{c.reader}
	reader, created := bufio.CreateConnectedPacketBatchReadWaiter(socketReader)
	if !created {
		return nil, false
	}
	rawConn, _ := socketReader.SyscallConn()
	return &clientPacketBatchReadWaiter{conn: c, reader: reader, rawConn: rawConn}, true
}

type clientPacketBatchReadWaiter struct {
	conn    *clientPacketConn
	reader  N.ConnectedPacketBatchReadWaiter
	options N.ReadWaitOptions

	// UDP_GRO (packet_batch_read_gro_linux.go): tried on the first read,
	// gro is the splitting reader if the socket accepted it.
	rawConn  syscall.RawConn
	groTried bool
	gro      N.ConnectedPacketBatchReadWaiter
}

func (w *clientPacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	if w.gro != nil {
		w.gro.InitializeReadWaiter(options)
	}
	return w.reader.InitializeReadWaiter(options)
}

func (w *clientPacketBatchReadWaiter) batchReader() N.ConnectedPacketBatchReadWaiter {
	if !w.groTried {
		w.groTried = true
		if w.rawConn != nil {
			w.gro = newGROBatchReader(w.conn, w.rawConn, w.options)
		}
	}
	if w.gro != nil {
		// stays in use after a single read turned UDP_GRO off: an entry
		// without the UDP_GRO cmsg is one datagram
		return w.gro
	}
	return w.reader
}

func (w *clientPacketBatchReadWaiter) WaitReadPackets() (buffers []*buf.Buffer, destinations []M.Socksaddr, err error) {
	reader := w.batchReader()
	for {
		buffers, _, err = reader.WaitReadConnectedPackets()
		if err != nil {
			return nil, nil, err
		}
		destinations = make([]M.Socksaddr, 0, len(buffers))
		opened := buffers[:0]
		var firstErr error
		for _, buffer := range buffers {
			destination, openErr := w.conn.readPacket(buffer)
			if openErr != nil {
				buffer.Release()
				if firstErr == nil {
					firstErr = openErr
				}
				continue
			}
			opened = append(opened, buffer)
			destinations = append(destinations, destination)
		}
		clear(buffers[len(opened):])
		if len(opened) > 0 {
			return opened, destinations, nil
		}
		if firstErr != nil {
			return nil, nil, firstErr
		}
		// An empty batch without an error: read again.
	}
}

func (w *clientPacketBatchReadWaiter) Upstream() any {
	return w.reader
}

// clientSocketReader presents the client's underlying conn to sing's batch
// reader factory. It reports the conn's raw socket only when reads may bypass
// every wrapper in between (N.SyscallConnForRead returns no SyscallReader).
type clientSocketReader struct {
	conn io.Reader
}

func (r *clientSocketReader) SyscallConn() (syscall.RawConn, error) {
	syscallReader, rawConn := N.SyscallConnForRead(r.conn)
	if syscallReader != nil || rawConn == nil {
		return nil, os.ErrInvalid
	}
	return rawConn, nil
}

func (r *clientSocketReader) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, err := r.conn.Read(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.Socksaddr{}, nil
}

func (r *clientSocketReader) Upstream() any {
	return r.conn
}
