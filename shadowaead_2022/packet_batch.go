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

// Upload batching for the client side of SIP022 UDP.
//
// When a packet copy hands the client conn several packets at once, each one
// is still sealed on its own, exactly as WritePacket does (own packet ID, own
// AEAD tag). The sealed packets then go to the connected UDP socket in one
// sendmmsg call. sing's batch writer also merges runs of same-sized packets
// into a single UDP GSO send. Every datagram on the wire is unchanged, so the
// server needs nothing new.
//
// The batch writer exists only when the underlying conn exposes a connected
// socket that writes may go to directly. That is a syscall.Conn, or wrappers
// that declare WriterReplaceable. Otherwise packet copies keep using
// WritePacket.
//
// SS2_DISABLE_UDP_BATCH=1 turns the batch writer off (used for A/B tests).

var disableUDPBatch = os.Getenv("SS2_DISABLE_UDP_BATCH") == "1"

var _ N.PacketBatchWriteCreator = (*clientPacketConn)(nil)

func (c *clientPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	if disableUDPBatch {
		return nil, false
	}
	conn, isWriter := c.AbstractConn.(io.Writer)
	if !isWriter {
		return nil, false
	}
	socketWriter := &clientSocketWriter{conn}
	// io_uring sendmsg instead of sendmmsg, opt-in (packet_batch_write_uring_linux.go)
	if rawConn, err := socketWriter.SyscallConn(); err == nil {
		if uringWriter := newUringConnectedWriter(rawConn, gsoDisabled(socketWriter)); uringWriter != nil {
			closeWriter := uringWriter.Close
			c.writerCloseHook.Store(&closeWriter)
			return &clientPacketBatchWriter{conn: c, writer: uringWriter}, true
		}
	}
	writer, created := bufio.CreateConnectedPacketBatchWriter(socketWriter)
	if !created {
		return nil, false
	}
	return &clientPacketBatchWriter{conn: c, writer: writer}, true
}

type clientPacketBatchWriter struct {
	conn   *clientPacketConn
	writer N.ConnectedPacketBatchWriter
}

func (w *clientPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	for index, buffer := range buffers {
		err := w.conn.sealPacket(buffer, destinations[index])
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	// Takes ownership of the buffers and releases them.
	return w.writer.WriteConnectedPacketBatch(buffers)
}

// clientSocketWriter presents the client's underlying conn to sing's batch
// writer factory. It reports the conn's raw socket only when writes may
// bypass every wrapper in between (N.SyscallConnForWrite returns no
// SyscallWriter). Its Upstream lets per-conn GSO policies (N.GSOControl)
// further down still apply.
type clientSocketWriter struct {
	conn io.Writer
}

func (w *clientSocketWriter) SyscallConn() (syscall.RawConn, error) {
	syscallWriter, rawConn := N.SyscallConnForWrite(w.conn)
	if syscallWriter != nil || rawConn == nil {
		return nil, os.ErrInvalid
	}
	return rawConn, nil
}

func (w *clientSocketWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	_, err := w.conn.Write(buffer.Bytes())
	return err
}

func (w *clientSocketWriter) Upstream() any {
	return w.conn
}
