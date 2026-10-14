//go:build linux

package shadowaead_2022

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// UDP_GRO for the client's batch reads (Linux).
//
// The daily phone's WiFi driver (Qualcomm FISA) already hands the server's
// datagrams up as aggregated SKB_GSO_UDP_L4 skbs: 80-88% of the skbs that
// reached the SS2022 socket carried 3-4.3 datagrams each (ebpf_sing-box
// experimental/udp_rx_shape, 2026-10-14). A socket without UDP_GRO makes
// udp_queue_rcv_skb split every one of them again and queue each piece on
// its own (~1 us of softirq per datagram, experimental/udp_gro_probe). With
// UDP_GRO the socket takes the aggregate whole: one recvmmsg entry holds
// several datagrams back to back, and a UDP_GRO control message gives their
// size (the last one may be shorter). They are split here into one packet
// buffer each, so readPacket still opens one SIP022 packet at a time.
//
// A coalesced entry can be up to 64 KiB, larger than the packet buffers
// callers hand out, so recvmmsg reads into pooled 64 KiB slots that are
// returned to the pool after every read (an idle connection holds none).
//
// UDP_GRO is only switched on when the batch reader actually reads, not
// when it is created: sing's copy loop may create a batch reader and then
// fall back to single reads. A single read must never see a coalesced
// entry, so every single-read path calls groState.leave first, which turns
// UDP_GRO off again for good. Aggregates queued before that are lost as
// unopenable packets (UDP loss), which does not happen in sing-box, whose
// eBPF inbound downlink always takes the batch path.
//
// SS2_DISABLE_UDP_GRO=1 keeps UDP_GRO off (for A/B tests).

var disableUDPGRO = os.Getenv("SS2_DISABLE_UDP_GRO") == "1"

const (
	groSlots    = 8
	groSlotSize = 1 << 16
	groOOBSize  = 64 // one UDP_GRO cmsg needs unix.CmsgSpace(4) = 24
)

var groSlotPool = sync.Pool{New: func() any {
	slot := make([]byte, groSlotSize)
	return &slot
}}

// groState records whether UDP_GRO is on for the client's socket.
type groState struct {
	on      atomic.Bool
	rawConn syscall.RawConn
}

func (s *groState) enable(rawConn syscall.RawConn) bool {
	if setUDPGRO(rawConn, 1) != nil {
		return false
	}
	s.rawConn = rawConn
	s.on.Store(true)
	return true
}

// leave turns UDP_GRO off before a single-datagram read.
func (s *groState) leave() {
	if s.on.Load() && s.on.CompareAndSwap(true, false) {
		_ = setUDPGRO(s.rawConn, 0)
	}
}

func setUDPGRO(rawConn syscall.RawConn, value int) error {
	var setErr error
	err := rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, value)
	})
	if err != nil {
		return err
	}
	return setErr
}

// newGROBatchReader switches UDP_GRO on for conn's socket and returns a
// reader that splits coalesced entries, or nil if the socket refuses it.
func newGROBatchReader(conn *clientPacketConn, rawConn syscall.RawConn, options N.ReadWaitOptions) N.ConnectedPacketBatchReadWaiter {
	if disableUDPGRO || !conn.gro.enable(rawConn) {
		return nil
	}
	reader := &groBatchReader{rawConn: rawConn}
	reader.InitializeReadWaiter(options)
	return reader
}

type groMmsghdr struct {
	hdr unix.Msghdr
	n   uint32
}

type groBatchReader struct {
	rawConn  syscall.RawConn
	options  N.ReadWaitOptions
	slots    [groSlots]*[]byte
	iovecs   [groSlots]unix.Iovec
	oobs     [groSlots][groOOBSize]byte
	msgvec   [groSlots]groMmsghdr
	readN    int
	lastN    int // entries returned by the last recvmmsg (tests)
	readErr  error
	readFunc func(fd uintptr) (done bool)
}

func (r *groBatchReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.options = options
	r.readFunc = r.read
	return false
}

func (r *groBatchReader) read(fd uintptr) (done bool) {
	for i := range r.msgvec {
		if r.slots[i] == nil {
			r.slots[i] = groSlotPool.Get().(*[]byte)
		}
		slot := *r.slots[i]
		r.iovecs[i] = unix.Iovec{Base: &slot[0]}
		r.iovecs[i].SetLen(len(slot))
		r.msgvec[i] = groMmsghdr{}
		r.msgvec[i].hdr.Iov = &r.iovecs[i]
		r.msgvec[i].hdr.SetIovlen(1)
		r.msgvec[i].hdr.Control = &r.oobs[i][0]
		r.msgvec[i].hdr.SetControllen(groOOBSize)
	}
	for {
		n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&r.msgvec[0])), groSlots, 0, 0, 0)
		switch errno {
		case 0:
			r.readN = int(n)
			r.readErr = nil
			if r.readN == 0 {
				r.readErr = io.EOF
			}
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
			r.releaseSlots()
			return false
		default:
			r.readErr = os.NewSyscallError("recvmmsg", errno)
		}
		return true
	}
}

func (r *groBatchReader) releaseSlots() {
	for i, slot := range r.slots {
		if slot != nil {
			groSlotPool.Put(slot)
			r.slots[i] = nil
		}
	}
}

func (r *groBatchReader) WaitReadConnectedPackets() (buffers []*buf.Buffer, destination M.Socksaddr, err error) {
	defer r.releaseSlots()
	err = r.rawConn.Read(r.readFunc)
	if err != nil {
		return
	}
	if r.readErr != nil {
		if r.readErr == io.EOF {
			return nil, M.Socksaddr{}, io.EOF
		}
		return nil, M.Socksaddr{}, E.Cause(r.readErr, "raw read")
	}
	for i := 0; i < r.readN; i++ {
		hdr := &r.msgvec[i].hdr
		if hdr.Flags&unix.MSG_TRUNC != 0 {
			// cannot happen with 64 KiB slots; never hand out a cut packet
			continue
		}
		data := (*r.slots[i])[:r.msgvec[i].n]
		segment := groSegmentSize(r.oobs[i][:hdr.Controllen])
		if segment <= 0 {
			segment = len(data)
		}
		for len(data) > 0 {
			size := min(segment, len(data))
			buffers = append(buffers, r.newBuffer(data[:size]))
			data = data[size:]
		}
	}
	r.lastN = r.readN
	r.readN = 0
	return
}

// newBuffer copies one datagram into a packet buffer with the headroom the
// destination asked for.
func (r *groBatchReader) newBuffer(datagram []byte) *buf.Buffer {
	buffer := r.options.NewPacketBuffer()
	if buffer.FreeLen() < len(datagram) {
		buffer.Release()
		buffer = buf.NewSize(r.options.FrontHeadroom + len(datagram) + r.options.RearHeadroom)
		if r.options.FrontHeadroom > 0 {
			buffer.Resize(r.options.FrontHeadroom, 0)
		}
		if r.options.RearHeadroom > 0 {
			buffer.Reserve(r.options.RearHeadroom)
		}
	}
	_, _ = buffer.Write(datagram)
	r.options.PostReturn(buffer)
	return buffer
}

// groSegmentSize returns the UDP_GRO segment size from a recvmsg control
// buffer, or 0 if the entry is a single datagram.
func groSegmentSize(oob []byte) int {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_UDP && message.Header.Type == unix.UDP_GRO && len(message.Data) >= 4 {
			return int(binary.NativeEndian.Uint32(message.Data))
		}
	}
	return 0
}
