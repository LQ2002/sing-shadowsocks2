//go:build linux

package shadowaead_2022

import (
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// groBatchReader is a recvmmsg reader for the client's connected UDP socket
// with UDP_GRO enabled (default on; SS2_UDP_GRO=0 turns it off).
//
// On the phone the NIC side already merges consecutive datagrams of a flow
// before the stack sees them: on LTE rmnet/the modem hands up GSO skbs
// (2026-10-15: 876 of 1172 skbs of a 9 MB download, ~8.4 KB each) and on
// WiFi the qca driver's FISA does the same (1258 of 1743 skbs carried
// 7912 datagrams). Without UDP_GRO on the socket udp_rcv splits each of them
// back into single datagrams (udp_unexpected_gso -> __udp_gso_segment),
// queues them one by one and wakes the reader per queueing. With UDP_GRO the
// merged skb is queued whole and recvmsg returns it in one piece with its
// segment size in a SOL_UDP/UDP_GRO cmsg; every segment is one SIP022
// datagram (sealed on its own by the server), so it is cut here at that size
// (the last segment may be shorter) and each piece is opened exactly as a
// datagram read on its own.
//
// A merged skb may be up to 64 KiB and is truncated (data lost) when the
// receive slot is smaller, so the slots are 64 KiB. They live in a slab
// shared through a sync.Pool and are held only inside one recvmmsg call;
// each segment is copied into a packet buffer of its own. Idle sessions hold
// no slab.
//
// Only this reader may read the socket once UDP_GRO is on: any other read
// would get a merged datagram it cannot open. The batch read waiter is the
// copy's reader for the whole session, so that holds in sing-box.

// On by default since 2026-10-16. On the phone (HTTP/3 download through
// sing-box, 4 rounds each on WiFi and LTE, sing-box io_uring on in both) the
// io_uring reader with GRO took sing-box CPU per MB 62% (WiFi) / 63% (LTE)
// below the recvmmsg build, against 58% / 61% without GRO; whole-system busy
// CPU per MB 52 vs 67 ms (WiFi), 47 vs 54 ms (LTE). This recvmmsg reader with
// GRO is the fallback; alone it saved 5% on WiFi.
// SS2_UDP_GRO=0 turns it off.
var enableUDPGRO = os.Getenv("SS2_UDP_GRO") != "0"

const (
	groSlots       = 8
	groSlotSize    = 65536
	groControlSize = 32 // CMSG_SPACE(sizeof(int)) on 64-bit is 24
)

type groSlab struct {
	data    []byte
	control []byte
	iovecs  [groSlots]unix.Iovec
	msgvec  [groSlots]keptMmsghdr
}

var groSlabPool = sync.Pool{New: func() any {
	return &groSlab{
		data:    make([]byte, groSlots*groSlotSize),
		control: make([]byte, groSlots*groControlSize),
	}
}}

func (s *groSlab) reset() {
	for i := range s.msgvec {
		s.iovecs[i] = unix.Iovec{Base: &s.data[i*groSlotSize]}
		s.iovecs[i].SetLen(groSlotSize)
		s.msgvec[i] = keptMmsghdr{}
		s.msgvec[i].hdr.Iov = &s.iovecs[i]
		s.msgvec[i].hdr.SetIovlen(1)
		s.msgvec[i].hdr.Control = &s.control[i*groControlSize]
		s.msgvec[i].hdr.SetControllen(groControlSize)
	}
}

// groSegmentSize returns the UDP_GRO segment size in the control data of a
// received message, or 0 when there is none (a datagram that was not merged).
func groSegmentSize(control []byte) int {
	for len(control) >= unix.SizeofCmsghdr {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		length := int(header.Len)
		if length < unix.SizeofCmsghdr || length > len(control) {
			return 0
		}
		if header.Level == unix.SOL_UDP && header.Type == unix.UDP_GRO && length >= unix.SizeofCmsghdr+4 {
			return int(*(*int32)(unsafe.Pointer(&control[unix.SizeofCmsghdr])))
		}
		aligned := (length + 7) &^ 7
		if aligned >= len(control) {
			return 0
		}
		control = control[aligned:]
	}
	return 0
}

type groBatchReader struct {
	rawConn     syscall.RawConn
	destination M.Socksaddr
	options     N.ReadWaitOptions
	out         []*buf.Buffer
	readErr     error
	readFunc    func(fd uintptr) (done bool)
}

// newGROBatchReader enables UDP_GRO on the connected socket behind rawConn
// and returns a reader for it, or nil when GRO is off, the socket is not
// connected, or the kernel refuses the option.
func newGROBatchReader(rawConn syscall.RawConn) N.ConnectedPacketBatchReadWaiter {
	if !enableUDPGRO {
		return nil
	}
	var destination M.Socksaddr
	err := rawConn.Control(func(fd uintptr) {
		peer, peerErr := unix.Getpeername(int(fd))
		if peerErr != nil {
			return
		}
		if unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1) != nil {
			return
		}
		destination = M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(peer)).Unwrap()
	})
	if err != nil || !destination.IsValid() {
		return nil
	}
	return &groBatchReader{rawConn: rawConn, destination: destination}
}

func (r *groBatchReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.options = options
	r.readFunc = r.read
	return false
}

func (r *groBatchReader) read(fd uintptr) (done bool) {
	slab := groSlabPool.Get().(*groSlab)
	defer groSlabPool.Put(slab)
	slab.reset()
	var count int
	for {
		n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&slab.msgvec[0])), groSlots, 0, 0, 0)
		switch errno {
		case 0:
			count = int(n)
		case syscall.EINTR, syscall.EMSGSIZE:
			// EMSGSIZE: an ICMP "fragmentation needed" reported on the
			// socket, not a read failure (packet_mtu.go)
			continue
		case syscall.EAGAIN:
			return false
		default:
			r.readErr = os.NewSyscallError("recvmmsg", errno)
			return true
		}
		break
	}
	if count == 0 {
		r.readErr = io.EOF
		return true
	}
	for i := 0; i < count; i++ {
		msg := &slab.msgvec[i]
		data := slab.data[i*groSlotSize : i*groSlotSize+int(msg.n)]
		segment := groSegmentSize(slab.control[i*groControlSize : i*groControlSize+int(msg.hdr.Controllen)])
		if segment <= 0 {
			segment = len(data)
		}
		for len(data) > 0 {
			piece := data[:min(segment, len(data))]
			data = data[len(piece):]
			buffer := r.options.NewPacketBuffer()
			if buffer.FreeLen() < len(piece) {
				buffer.Release()
				continue
			}
			common := buffer.Extend(len(piece))
			copy(common, piece)
			r.options.PostReturn(buffer)
			r.out = append(r.out, buffer)
		}
	}
	return true
}

func (r *groBatchReader) WaitReadConnectedPackets() (buffers []*buf.Buffer, destination M.Socksaddr, err error) {
	for {
		err = r.rawConn.Read(r.readFunc)
		if err == nil && r.readErr != nil {
			err = r.readErr
			r.readErr = nil
			if err != io.EOF {
				err = E.Cause(err, "raw read")
			}
		}
		if err != nil {
			buf.ReleaseMulti(r.out)
			clear(r.out)
			r.out = r.out[:0]
			return nil, M.Socksaddr{}, err
		}
		if len(r.out) > 0 {
			break
		}
	}
	buffers = make([]*buf.Buffer, len(r.out))
	copy(buffers, r.out)
	clear(r.out)
	r.out = r.out[:0]
	return buffers, r.destination, nil
}

func (r *groBatchReader) Upstream() any {
	return r.rawConn
}
