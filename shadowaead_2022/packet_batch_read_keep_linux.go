//go:build linux

package shadowaead_2022

import (
	"io"
	"os"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// keptBatchReader is the recvmmsg reader under the client's batch read
// waiter (Linux). It does what sing's connected batch reader
// (bufio.syscallPacketBatchReadWaiter) does, except that packet buffers
// recvmmsg did not fill stay here for the next call.
//
// sing's reader takes a fresh packet buffer for every one of the BatchSize
// (64 in sing-box's copy) recvmmsg slots on each call, and again after every
// EAGAIN, then releases the ones left empty. A batch is usually a few
// datagrams, so that was ~60 pool round trips per read: releaseBuffers alone
// was 2.9% of sing-box CPU during an HTTP/3 download on the daily phone
// (2026-10-13). sing-box's eBPF inbound reader had the same pattern and the
// same fix (Ref_sing-box common/udpio, 49cc94ef4).
//
// The price is up to BatchSize packet buffers held while the socket is idle;
// they are released when the waiter is re-initialised or the read fails.
//
// SS2_DISABLE_UDP_KEEP_BUFFERS=1 uses sing's reader instead (for A/B tests).

var disableUDPKeepBuffers = os.Getenv("SS2_DISABLE_UDP_KEEP_BUFFERS") == "1"

type keptMmsghdr struct {
	hdr unix.Msghdr
	n   uint32
}

type keptBatchReader struct {
	rawConn     syscall.RawConn
	destination M.Socksaddr
	options     N.ReadWaitOptions
	buffers     []*buf.Buffer
	iovecs      []unix.Iovec
	msgvec      []keptMmsghdr
	readN       int
	readErr     error
	readFunc    func(fd uintptr) (done bool)
}

// newKeptBatchReader returns a reader for the connected socket behind
// rawConn, or nil when the socket is not connected (sing's factory makes the
// same check).
func newKeptBatchReader(rawConn syscall.RawConn) N.ConnectedPacketBatchReadWaiter {
	if disableUDPKeepBuffers {
		return nil
	}
	var destination M.Socksaddr
	err := rawConn.Control(func(fd uintptr) {
		peer, peerErr := unix.Getpeername(int(fd))
		if peerErr == nil {
			destination = M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(peer)).Unwrap()
		}
	})
	if err != nil || !destination.IsValid() {
		return nil
	}
	return &keptBatchReader{rawConn: rawConn, destination: destination}
}

func (r *keptBatchReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.releaseBuffers()
	if options.BatchSize <= 0 {
		options.BatchSize = 64 // bufio.DefaultPacketReadBatchSize
	}
	r.options = options
	r.buffers = make([]*buf.Buffer, options.BatchSize)
	r.iovecs = make([]unix.Iovec, options.BatchSize)
	r.msgvec = make([]keptMmsghdr, options.BatchSize)
	r.readFunc = r.read
	return false
}

func (r *keptBatchReader) read(fd uintptr) (done bool) {
	for i := range r.msgvec {
		buffer := r.buffers[i]
		if buffer == nil {
			buffer = r.options.NewPacketBuffer()
			r.buffers[i] = buffer
		}
		r.iovecs[i] = buffer.Iovec(buffer.FreeLen())
		r.msgvec[i] = keptMmsghdr{}
		r.msgvec[i].hdr.Iov = &r.iovecs[i]
		r.msgvec[i].hdr.SetIovlen(1)
	}
	for {
		n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&r.msgvec[0])), uintptr(len(r.msgvec)), 0, 0, 0)
		switch errno {
		case 0:
			r.readN = int(n)
			r.readErr = nil
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
			// unfilled buffers stay for the next call
			return false
		default:
			r.readN = 0
			r.readErr = os.NewSyscallError("recvmmsg", errno)
		}
		break
	}
	if r.readN == 0 && r.readErr == nil {
		r.readErr = io.EOF
	}
	for i := 0; i < r.readN; i++ {
		buffer := r.buffers[i]
		buffer.Truncate(int(r.msgvec[i].n))
		r.options.PostReturn(buffer)
	}
	return true
}

func (r *keptBatchReader) WaitReadConnectedPackets() (buffers []*buf.Buffer, destination M.Socksaddr, err error) {
	err = r.rawConn.Read(r.readFunc)
	if err != nil {
		r.releaseBuffers()
		return
	}
	if r.readErr != nil {
		readErr := r.readErr
		r.releaseBuffers()
		if readErr == io.EOF {
			return nil, M.Socksaddr{}, io.EOF
		}
		return nil, M.Socksaddr{}, E.Cause(readErr, "raw read")
	}
	buffers = make([]*buf.Buffer, r.readN)
	for i := 0; i < r.readN; i++ {
		buffers[i] = r.buffers[i]
		r.buffers[i] = nil
		r.iovecs[i] = unix.Iovec{}
	}
	r.readN = 0
	return buffers, r.destination, nil
}

func (r *keptBatchReader) releaseBuffers() {
	clear(r.iovecs)
	clear(r.msgvec)
	buf.ReleaseMulti(r.buffers)
	clear(r.buffers)
	r.readN = 0
	r.readErr = nil
}

func (r *keptBatchReader) Upstream() any {
	return r.rawConn
}
