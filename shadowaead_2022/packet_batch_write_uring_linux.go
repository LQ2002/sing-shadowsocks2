//go:build linux

package shadowaead_2022

import (
	"net"
	"os"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// uringConnectedWriter sends the client's sealed UDP batches to the server
// with io_uring IORING_OP_SENDMSG instead of sendmmsg (experiment, opt-in:
// SS2_UDP_IOURING_SEND=1).
//
// Batching is sing's (bufio packet_batch_offload_linux.go): consecutive
// datagrams of equal size (the last may be shorter) become one sendmsg with
// UDP_SEGMENT, up to 64 segments and 65507 bytes. All messages of a batch go
// in as SQEs and one io_uring_enter submits them and waits for their
// completions, so a batch is one syscall, as with sendmmsg; the experiment
// measures whether it is cheaper. The ring is guarded by a mutex (no thread
// affinity needed: a send that cannot complete at once is retried by
// io_uring and completes before the wait returns).

// gsoDisabled is the walk N.IsGSODisabled does in sing-box's sing (a
// DisableGSO() policy anywhere below the writer), written out here because
// this module's sing version predates that helper.
func gsoDisabled(conn any) bool {
	for {
		if policy, loaded := conn.(interface{ DisableGSO() bool }); loaded {
			return policy.DisableGSO()
		}
		if writer, loaded := conn.(N.WithUpstreamWriter); loaded {
			if upstream := writer.UpstreamWriter(); upstream != nil {
				conn = upstream
				continue
			}
		}
		switch upstream := conn.(type) {
		case common.WithUpstream:
			conn = upstream.Upstream()
		case interface{ NetConn() net.Conn }:
			conn = upstream.NetConn()
		default:
			return false
		}
	}
}

var enableUDPIOUringSend = os.Getenv("SS2_UDP_IOURING_SEND") == "1"

const (
	uringSendSQEntries = 64
	uringSendCQEntries = 128
	opSendMsg          = 9
	uringSendMaxSegs   = 64
	uringSendMaxBytes  = 65507
)

type uringConnectedWriter struct {
	rawConn syscall.RawConn
	fd      int
	access  sync.Mutex
	noGSO   bool
	closed  bool

	ringFD  int
	ringMem []byte
	sqesMem []byte
	sqHead  *uint32
	sqTail  *uint32
	sqMask  uint32
	sqArray unsafe.Pointer
	sqes    unsafe.Pointer
	cqHead  *uint32
	cqTail  *uint32
	cqMask  uint32
	cqes    unsafe.Pointer

	iovecs   []unix.Iovec
	messages []unix.Msghdr
	controls [][24]byte
	runs     [][2]int
	results  []int32
}

// newUringConnectedWriter returns nil unless SS2_UDP_IOURING_SEND=1.
func newUringConnectedWriter(rawConn syscall.RawConn, noGSO bool) *uringConnectedWriter {
	if !enableUDPIOUringSend || rawConn == nil {
		return nil
	}
	fd := -1
	_ = rawConn.Control(func(rawFD uintptr) { fd = int(rawFD) })
	if fd < 0 {
		return nil
	}
	return &uringConnectedWriter{rawConn: rawConn, fd: fd, noGSO: noGSO, ringFD: -1}
}

func (w *uringConnectedWriter) setup() error {
	var params uringParams
	params.flags = setupCQSize
	params.cqEntries = uringSendCQEntries
	ringFD, _, errno := unix.RawSyscall(sysIOURingSetup, uringSendSQEntries, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_setup", errno)
	}
	w.ringFD = int(ringFD)
	if params.features&featSingleMmap == 0 {
		return E.New("io_uring without SINGLE_MMAP")
	}
	size := max(params.sqOff.array+params.sqEntries*4, params.cqOff.cqes+params.cqEntries*uint32(unsafe.Sizeof(uringCQE{})))
	ringMem, err := unix.Mmap(w.ringFD, offSQRing, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring rings")
	}
	w.ringMem = ringMem
	sqesMem, err := unix.Mmap(w.ringFD, offSQEs, int(params.sqEntries)*int(unsafe.Sizeof(uringSQE{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring sqes")
	}
	w.sqesMem = sqesMem
	base := unsafe.Pointer(&ringMem[0])
	w.sqHead = (*uint32)(unsafe.Add(base, params.sqOff.head))
	w.sqTail = (*uint32)(unsafe.Add(base, params.sqOff.tail))
	w.sqMask = *(*uint32)(unsafe.Add(base, params.sqOff.ringMask))
	w.sqArray = unsafe.Add(base, params.sqOff.array)
	w.sqes = unsafe.Pointer(&sqesMem[0])
	w.cqHead = (*uint32)(unsafe.Add(base, params.cqOff.head))
	w.cqTail = (*uint32)(unsafe.Add(base, params.cqOff.tail))
	w.cqMask = *(*uint32)(unsafe.Add(base, params.cqOff.ringMask))
	w.cqes = unsafe.Add(base, params.cqOff.cqes)
	return nil
}

func (w *uringConnectedWriter) pushSQE(entry uringSQE) {
	tail := *w.sqTail
	index := tail & w.sqMask
	*(*uringSQE)(unsafe.Add(w.sqes, uintptr(index)*unsafe.Sizeof(uringSQE{}))) = entry
	*(*uint32)(unsafe.Add(w.sqArray, uintptr(index)*4)) = index
	atomic.StoreUint32(w.sqTail, tail+1)
}

func (w *uringConnectedWriter) submitAndWait(count int) error {
	toSubmit := atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
	reaped := 0
	for reaped < count {
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(w.ringFD), uintptr(toSubmit), uintptr(count-reaped), enterGetEvents, 0, 0)
		switch errno {
		case 0, unix.EINTR, unix.EAGAIN, unix.EBUSY:
		default:
			return os.NewSyscallError("io_uring_enter", errno)
		}
		toSubmit = atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
		head := atomic.LoadUint32(w.cqHead)
		tail := atomic.LoadUint32(w.cqTail)
		for ; head != tail; head++ {
			cqe := (*uringCQE)(unsafe.Add(w.cqes, uintptr(head&w.cqMask)*unsafe.Sizeof(uringCQE{})))
			if int(cqe.userData) < len(w.results) {
				w.results[cqe.userData] = cqe.res
				reaped++
			}
		}
		atomic.StoreUint32(w.cqHead, head)
	}
	return nil
}

// WriteConnectedPacketBatch takes ownership of the buffers.
func (w *uringConnectedWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	defer buf.ReleaseMulti(buffers)
	if w.closed {
		return net.ErrClosed
	}
	if w.ringFD < 0 {
		if err := w.setup(); err != nil {
			w.release()
			return err
		}
	}
	count := len(buffers)
	if cap(w.iovecs) < count {
		w.iovecs = make([]unix.Iovec, count)
		w.messages = make([]unix.Msghdr, count)
		w.controls = make([][24]byte, count)
	}
	w.iovecs, w.messages, w.controls = w.iovecs[:count], w.messages[:count], w.controls[:count]
	w.runs = w.runs[:0]
	for start := 0; start < count; {
		end := start + 1
		if !w.noGSO {
			segment := buffers[start].Len()
			total := segment
			for end < count && end-start < uringSendMaxSegs {
				next := buffers[end].Len()
				if next == 0 || next > segment || total+next > uringSendMaxBytes {
					break
				}
				total += next
				end++
				if next < segment {
					break
				}
			}
		}
		w.runs = append(w.runs, [2]int{start, end})
		start = end
	}
	for offset := 0; offset < len(w.runs); offset += uringSendSQEntries {
		runs := w.runs[offset:min(len(w.runs), offset+uringSendSQEntries)]
		if cap(w.results) < len(runs) {
			w.results = make([]int32, len(runs))
		}
		w.results = w.results[:len(runs)]
		for index, run := range runs {
			start, end := run[0], run[1]
			for i := start; i < end; i++ {
				w.iovecs[i] = buffers[i].Iovec(buffers[i].Len())
			}
			message := &w.messages[index]
			*message = unix.Msghdr{}
			message.Iov = &w.iovecs[start]
			message.SetIovlen(end - start)
			if end-start > 1 {
				control := w.controls[index][:unix.CmsgSpace(2)]
				clear(control)
				header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
				header.Level = unix.IPPROTO_UDP
				header.Type = unix.UDP_SEGMENT
				header.SetLen(unix.CmsgLen(2))
				*(*uint16)(unsafe.Pointer(&control[unix.CmsgLen(0)])) = uint16(buffers[start].Len())
				message.Control = &control[0]
				message.SetControllen(len(control))
			}
			w.pushSQE(uringSQE{opcode: opSendMsg, fd: int32(w.fd), addr: uint64(uintptr(unsafe.Pointer(message))), len: 1, userData: uint64(index)})
		}
		if err := w.submitAndWait(len(runs)); err != nil {
			return err
		}
		for index, run := range runs {
			res := w.results[index]
			if res >= 0 {
				continue
			}
			errno := syscall.Errno(-res)
			if run[1]-run[0] > 1 && (errno == unix.EINVAL || errno == unix.EIO || errno == unix.ENOPROTOOPT || errno == unix.EOPNOTSUPP) {
				w.noGSO = true
				for i := run[0]; i < run[1]; i++ {
					if err := w.sendOne(buffers[i]); err != nil {
						return err
					}
				}
				continue
			}
			return os.NewSyscallError("io_uring sendmsg", errno)
		}
	}
	return nil
}

func (w *uringConnectedWriter) sendOne(buffer *buf.Buffer) error {
	var sendErr error
	err := w.rawConn.Write(func(fd uintptr) bool {
		_, sendErr = unix.Write(int(fd), buffer.Bytes())
		return sendErr != unix.EAGAIN
	})
	if err != nil {
		return err
	}
	return sendErr
}

func (w *uringConnectedWriter) Close() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	w.release()
}

func (w *uringConnectedWriter) release() {
	if w.ringFD >= 0 {
		_ = unix.Close(w.ringFD)
		w.ringFD = -1
	}
	if w.ringMem != nil {
		_ = unix.Munmap(w.ringMem)
		w.ringMem = nil
	}
	if w.sqesMem != nil {
		_ = unix.Munmap(w.sqesMem)
		w.sqesMem = nil
	}
}
