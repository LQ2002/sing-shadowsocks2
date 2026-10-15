//go:build linux

package shadowaead_2022

import (
	"io"
	"os"
	"runtime"
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

// uringBatchReader is an io_uring alternative to keptBatchReader for the
// client's connected UDP socket (default on; SS2_UDP_IOURING=0 turns it off).
//
// One multishot IORING_OP_RECVMSG is armed on the socket with a provided
// buffer ring, so every datagram that arrives lands in a ring buffer without
// a read syscall of ours. The kernel does the receive in task_work of the
// thread that armed it, so the reading goroutine is locked to one OS thread
// while the reader is alive; when the completion queue is empty it blocks in
// io_uring_enter(GETEVENTS), and an arriving datagram wakes that thread
// (TWA_SIGNAL), which runs the receive and returns. Compared with the
// recvmmsg reader there is no epoll wait through the Go netpoller and no
// trailing recvmmsg that returns EAGAIN.
//
// SINGLE_ISSUER/DEFER_TASKRUN are not used: they would forbid the cancel
// below from another thread.
//
// Payloads are copied out of the ring buffer into a packet buffer from the
// copy loop's pool, and the ring buffer is handed back at once.
//
// Close: io_uring holds its own reference to the socket file, so closing the
// fd would not end the armed receive, and shutdown(SHUT_RD) does not either
// (a non-blocking UDP receive ignores RCV_SHUTDOWN and keeps returning
// EAGAIN). clientPacketConn.Close therefore calls shutdown (closeHook): a
// reader blocked in io_uring_enter gets an IORING_OP_ASYNC_CANCEL for its
// receive and returns io.EOF; an idle reader's ring is closed outright.

// On by default since 2026-10-16 (see enableUDPGRO for the numbers); when
// io_uring cannot be set up the reader falls back to recvmmsg on its own.
// SS2_UDP_IOURING=0 turns it off.
var enableUDPIOUring = os.Getenv("SS2_UDP_IOURING") != "0"

// Wait variants (experiment). SS2_UDP_IOURING_WAIT=netpoll: the reader does
// not lock its thread or block in io_uring_enter; the ring fd (pollable:
// EPOLLIN while completions are queued) is handed to the Go netpoller and
// the goroutine parks there like on a socket. The receive task_work then
// runs on whichever thread armed the multishot receive, which the kernel
// wakes (TWA_SIGNAL) for every batch, so a batch costs that wake plus the
// netpoller's; the variant trades that for no dedicated thread per reader.
// SS2_UDP_IOURING_COOP=1 adds IORING_SETUP_COOP_TASKRUN (task_work notified
// without an IPI; a sleeping arming thread is still woken).
//
// With UDP_GRO on as well the socket gets UDP_GRO (see
// packet_batch_read_gro_linux.go): the receive reserves room for the
// UDP_GRO cmsg and the ring buffers are 64 KiB, since a merged datagram is
// truncated (lost) in a smaller one. To bound memory there are only
// uringGROBufferCount of them; when all are in use the multishot receive
// ends with ENOBUFS, the datagrams stay queued on the socket, and the
// receive is re-armed once the buffers are back.
var (
	udpIOUringNetpoll = os.Getenv("SS2_UDP_IOURING_WAIT") == "netpoll"
	udpIOUringCoop    = os.Getenv("SS2_UDP_IOURING_COOP") == "1"
)

const (
	uringRecvTag     = 1
	uringBufferGroup = 7
	uringBufferCount = 64   // power of two
	uringBufferSize  = 2048 // recvmsg_out header + one datagram
	// UDP_GRO: recvmsg_out header + reserved cmsg room + a merged datagram
	uringGROBufferCount = 8 // power of two
	uringGROBufferSize  = uringRecvOutSize + groControlSize + groSlotSize
	uringRecvOutSize = 16   // struct io_uring_recvmsg_out
	uringSQEntries   = 8
	uringCQEntries   = 256
	sysIOURingSetup  = 425
	sysIOURingEnter  = 426
	sysIOURingReg    = 427
	setupCQSize      = 1 << 3
	setupCoopTaskrun = 1 << 8
	sqCQOverflow     = 1 << 1
	featSingleMmap   = 1 << 0
	enterGetEvents   = 1 << 0
	opRecvMsg        = 10
	opAsyncCancel    = 14
	uringCancelTag   = 2
	sqeBufferSelect  = 1 << 5
	recvMultishot    = 1 << 1
	cqeFBuffer       = 1 << 0
	cqeFMore         = 1 << 1
	cqeBufferShift   = 16
	registerPbufRing = 22
	unregisterPbuf   = 23
	offSQRing        = 0
	offSQEs          = 0x10000000
)

type uringSQOffsets struct {
	head, tail, ringMask, ringEntries, flags, dropped, array, resv1 uint32
	userAddr                                                        uint64
}

type uringCQOffsets struct {
	head, tail, ringMask, ringEntries, overflow, cqes, flags, resv1 uint32
	userAddr                                                        uint64
}

type uringParams struct {
	sqEntries, cqEntries, flags, sqThreadCPU, sqThreadIdle, features, wqFD uint32
	resv                                                                   [3]uint32
	sqOff                                                                  uringSQOffsets
	cqOff                                                                  uringCQOffsets
}

type uringSQE struct {
	opcode      uint8
	flags       uint8
	ioprio      uint16
	fd          int32
	off         uint64
	addr        uint64
	len         uint32
	opFlags     uint32
	userData    uint64
	bufGroup    uint16
	personality uint16
	spliceFD    int32
	addr3       uint64
	pad         uint64
}

type uringCQE struct {
	userData uint64
	res      int32
	flags    uint32
}

type uringBufRegister struct {
	ringAddr    uint64
	ringEntries uint32
	bgid        uint16
	flags       uint16
	resv        [3]uint64
}

type uringBuf struct {
	addr uint64
	len  uint32
	bid  uint16
	tail uint16 // only meaningful in entry 0: the ring tail
}

func init() {
	var p uringParams
	var sqe uringSQE
	var reg uringBufRegister
	if unsafe.Sizeof(p) != 120 || unsafe.Sizeof(sqe) != 64 || unsafe.Sizeof(reg) != 40 ||
		unsafe.Sizeof(uringCQE{}) != 16 || unsafe.Sizeof(uringBuf{}) != 16 {
		panic("shadowaead_2022: io_uring ABI size mismatch")
	}
}

type uringBatchReader struct {
	rawConn     syscall.RawConn
	fd          int
	destination M.Socksaddr
	options     N.ReadWaitOptions

	ringFD  int
	ringMem []byte
	sqesMem []byte
	bufRing []byte
	slab    []byte
	sqHead  *uint32
	sqTail  *uint32
	sqMask  uint32
	sqArray unsafe.Pointer
	sqes    unsafe.Pointer
	cqHead  *uint32
	cqTail  *uint32
	cqMask  uint32
	cqes    unsafe.Pointer
	sqFlags *uint32
	bufTail uint16
	// gro: UDP_GRO is on for the socket; bufCount/bufSize are the ring
	// buffers' (uringBuffer* or uringGROBuffer*), control the cmsg room
	// reserved in front of each payload
	gro      bool
	bufCount int
	bufSize  int
	control  int
	// netpoll variant: the ring fd as an *os.File registered with the Go
	// netpoller, and its RawConn
	ringFile *os.File
	ringRaw  syscall.RawConn
	msghdr   unix.Msghdr
	armed    bool
	locked   bool
	eof      bool
	pending  []*buf.Buffer
	closed   atomic.Bool
	shutOnce sync.Once
	// access guards the ring memory against release from another goroutine
	// (shutdown via clientPacketConn.Close); inEnter marks the reader inside
	// io_uring_enter, where it does not touch that memory.
	access  sync.Mutex
	inEnter bool
	// fallback is the recvmmsg reader this session uses after its ring
	// could not be set up; only the reading goroutine touches it.
	fallback N.ConnectedPacketBatchReadWaiter
}

// io_uring is probed once per process with the reader's own setup (ring,
// mmaps, PBUF_RING registration): when the kernel lacks it, has it disabled
// (io_uring_disabled), or the process may not use it, every session gets the
// recvmmsg reader from the start.
var uringProbe struct {
	once sync.Once
	ok   bool
}

func uringAvailable() bool {
	uringProbe.once.Do(func() {
		probe := &uringBatchReader{ringFD: -1, bufCount: 2, bufSize: uringBufferSize}
		uringProbe.ok = probe.setup() == nil
		probe.release()
	})
	return uringProbe.ok
}

// newUringBatchReader returns the reader and the function the conn's Close
// must call, or nil when SS2_UDP_IOURING=0 or the socket is not
// connected.
func newUringBatchReader(rawConn syscall.RawConn) (N.ConnectedPacketBatchReadWaiter, func()) {
	if !enableUDPIOUring || !uringAvailable() {
		return nil, nil
	}
	var destination M.Socksaddr
	fd := -1
	err := rawConn.Control(func(rawFD uintptr) {
		peer, peerErr := unix.Getpeername(int(rawFD))
		if peerErr == nil {
			destination = M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(peer)).Unwrap()
			fd = int(rawFD)
		}
	})
	if err != nil || !destination.IsValid() || fd < 0 {
		return nil, nil
	}
	reader := &uringBatchReader{rawConn: rawConn, fd: fd, destination: destination, ringFD: -1,
		bufCount: uringBufferCount, bufSize: uringBufferSize}
	if enableUDPGRO && unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_GRO, 1) == nil {
		reader.gro = true
		reader.bufCount = uringGROBufferCount
		reader.bufSize = uringGROBufferSize
		reader.control = groControlSize
	}
	return reader, reader.shutdown
}

func (r *uringBatchReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	if options.BatchSize <= 0 {
		options.BatchSize = 64
	}
	r.options = options
	return false
}

// shutdown wakes a reader blocked in io_uring_enter; see the type comment.
// When the reader is not inside io_uring_enter (its copy loop may already
// have stopped calling it), the ring is released here so neither the ring
// nor the socket reference it holds can leak.
func (r *uringBatchReader) shutdown() {
	r.closed.Store(true)
	r.access.Lock()
	defer r.access.Unlock()
	if !r.inEnter {
		r.release()
		return
	}
	r.shutOnce.Do(func() {
		r.pushSQE(uringSQE{opcode: opAsyncCancel, fd: -1, addr: uringRecvTag, userData: uringCancelTag})
		toSubmit := atomic.LoadUint32(r.sqTail) - atomic.LoadUint32(r.sqHead)
		_, _, _ = unix.Syscall6(sysIOURingEnter, uintptr(r.ringFD), uintptr(toSubmit), 0, 0, 0, 0)
	})
}

func (r *uringBatchReader) setup() error {
	var params uringParams
	params.flags = setupCQSize
	if udpIOUringCoop {
		params.flags |= setupCoopTaskrun
	}
	params.cqEntries = uringCQEntries
	ringFD, _, errno := unix.RawSyscall(sysIOURingSetup, uringSQEntries, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_setup", errno)
	}
	r.ringFD = int(ringFD)
	if udpIOUringNetpoll {
		if err := unix.SetNonblock(r.ringFD, true); err != nil {
			return E.Cause(err, "set io_uring fd non-blocking")
		}
		// os.File owns the fd from here on; release closes it through the
		// file so the netpoller lets go of it first.
		r.ringFile = os.NewFile(uintptr(r.ringFD), "io_uring")
		ringRaw, err := r.ringFile.SyscallConn()
		if err != nil {
			return E.Cause(err, "io_uring fd raw conn")
		}
		r.ringRaw = ringRaw
	}
	if params.features&featSingleMmap == 0 {
		return E.New("io_uring without SINGLE_MMAP")
	}
	sqSize := params.sqOff.array + params.sqEntries*4
	cqSize := params.cqOff.cqes + params.cqEntries*uint32(unsafe.Sizeof(uringCQE{}))
	size := max(sqSize, cqSize)
	ringMem, err := unix.Mmap(r.ringFD, offSQRing, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring rings")
	}
	r.ringMem = ringMem
	sqesMem, err := unix.Mmap(r.ringFD, offSQEs, int(params.sqEntries)*int(unsafe.Sizeof(uringSQE{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring sqes")
	}
	r.sqesMem = sqesMem
	base := unsafe.Pointer(&ringMem[0])
	r.sqHead = (*uint32)(unsafe.Add(base, params.sqOff.head))
	r.sqTail = (*uint32)(unsafe.Add(base, params.sqOff.tail))
	r.sqMask = *(*uint32)(unsafe.Add(base, params.sqOff.ringMask))
	r.sqArray = unsafe.Add(base, params.sqOff.array)
	r.sqes = unsafe.Pointer(&sqesMem[0])
	r.cqHead = (*uint32)(unsafe.Add(base, params.cqOff.head))
	r.cqTail = (*uint32)(unsafe.Add(base, params.cqOff.tail))
	r.cqMask = *(*uint32)(unsafe.Add(base, params.cqOff.ringMask))
	r.cqes = unsafe.Add(base, params.cqOff.cqes)
	r.sqFlags = (*uint32)(unsafe.Add(base, params.sqOff.flags))

	bufRing, err := unix.Mmap(-1, 0, r.bufCount*int(unsafe.Sizeof(uringBuf{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return E.Cause(err, "mmap io_uring buffer ring")
	}
	r.bufRing = bufRing
	r.slab = make([]byte, r.bufCount*r.bufSize)
	if r.control > 0 {
		r.msghdr.SetControllen(r.control)
	}
	reg := uringBufRegister{
		ringAddr:    uint64(uintptr(unsafe.Pointer(&bufRing[0]))),
		ringEntries: uint32(r.bufCount),
		bgid:        uringBufferGroup,
	}
	_, _, errno = unix.Syscall6(sysIOURingReg, uintptr(r.ringFD), registerPbufRing, uintptr(unsafe.Pointer(&reg)), 1, 0, 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_register(PBUF_RING)", errno)
	}
	for bid := range r.bufCount {
		r.provide(uint16(bid))
	}
	r.publishBuffers()
	return nil
}

func (r *uringBatchReader) bufEntry(index uint16) *uringBuf {
	return (*uringBuf)(unsafe.Add(unsafe.Pointer(&r.bufRing[0]), uintptr(int(index)&(r.bufCount-1))*unsafe.Sizeof(uringBuf{})))
}

// provide queues ring buffer bid for the kernel; publishBuffers makes the
// queued entries visible by storing the new tail.
func (r *uringBatchReader) provide(bid uint16) {
	entry := r.bufEntry(r.bufTail)
	entry.addr = uint64(uintptr(unsafe.Pointer(&r.slab[int(bid)*r.bufSize])))
	entry.len = uint32(r.bufSize)
	// Entry 0's bid shares a 32-bit word with the ring tail; publishBuffers
	// stores that word whole.
	entry.bid = bid
	r.bufTail++
}

func (r *uringBatchReader) publishBuffers() {
	first := (*uringBuf)(unsafe.Pointer(&r.bufRing[0]))
	word := uint32(first.bid) | uint32(r.bufTail)<<16
	atomic.StoreUint32((*uint32)(unsafe.Add(unsafe.Pointer(&r.bufRing[0]), 12)), word)
}

// pushSQE queues one submission; access is held.
func (r *uringBatchReader) pushSQE(entry uringSQE) {
	tail := *r.sqTail
	index := tail & r.sqMask
	*(*uringSQE)(unsafe.Add(r.sqes, uintptr(index)*unsafe.Sizeof(uringSQE{}))) = entry
	*(*uint32)(unsafe.Add(r.sqArray, uintptr(index)*4)) = index
	atomic.StoreUint32(r.sqTail, tail+1)
}

func (r *uringBatchReader) arm() {
	r.pushSQE(uringSQE{
		opcode:   opRecvMsg,
		flags:    sqeBufferSelect,
		ioprio:   recvMultishot,
		fd:       int32(r.fd),
		addr:     uint64(uintptr(unsafe.Pointer(&r.msghdr))),
		userData: uringRecvTag,
		bufGroup: uringBufferGroup,
	})
	r.armed = true
}

// enter submits queued SQEs and, when wait is set, blocks until at least one
// completion (running the deferred receive task_work in this thread).
func (r *uringBatchReader) enter(wait bool) error {
	toSubmit := atomic.LoadUint32(r.sqTail) - atomic.LoadUint32(r.sqHead)
	var minComplete, flags uintptr
	if wait {
		minComplete, flags = 1, enterGetEvents
	}
	if toSubmit == 0 && !wait {
		return nil
	}
	if r.ringRaw != nil {
		return r.enterNetpoll(toSubmit, wait)
	}
	for {
		ringFD := r.ringFD
		r.inEnter = true
		r.access.Unlock()
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(ringFD), uintptr(toSubmit), minComplete, flags, 0, 0)
		r.access.Lock()
		r.inEnter = false
		if r.ringFD < 0 {
			return io.EOF
		}
		switch errno {
		case 0:
			return nil
		case unix.EINTR, unix.EAGAIN, unix.EBUSY:
			if !wait {
				return nil
			}
			toSubmit = atomic.LoadUint32(r.sqTail) - atomic.LoadUint32(r.sqHead)
			continue
		default:
			return os.NewSyscallError("io_uring_enter", errno)
		}
	}
}

// enterNetpoll is enter for the netpoll variant: submit without waiting,
// then park the goroutine in the Go netpoller until the ring fd reports
// queued completions.
func (r *uringBatchReader) enterNetpoll(toSubmit uint32, wait bool) error {
	if toSubmit > 0 {
		for {
			_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(r.ringFD), uintptr(toSubmit), 0, 0, 0, 0)
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 && errno != unix.EAGAIN && errno != unix.EBUSY {
				return os.NewSyscallError("io_uring_enter", errno)
			}
			break
		}
	}
	if !wait {
		return nil
	}
	ringFD := r.ringFD
	r.inEnter = true
	r.access.Unlock()
	err := r.ringRaw.Read(func(uintptr) bool {
		if atomic.LoadUint32(r.cqHead) != atomic.LoadUint32(r.cqTail) {
			return true
		}
		// Completions that did not fit the CQ wait in the kernel's
		// overflow list until an io_uring_enter(GETEVENTS) flushes them.
		if atomic.LoadUint32(r.sqFlags)&sqCQOverflow != 0 {
			_, _, _ = unix.Syscall6(sysIOURingEnter, uintptr(ringFD), 0, 0, enterGetEvents, 0, 0)
			return atomic.LoadUint32(r.cqHead) != atomic.LoadUint32(r.cqTail)
		}
		return false
	})
	r.access.Lock()
	r.inEnter = false
	if r.ringFD < 0 {
		return io.EOF
	}
	if err != nil {
		return E.Cause(err, "wait io_uring completions")
	}
	return nil
}

// reap moves completed datagrams into r.pending. It returns an error for a
// failed receive and sets r.eof when the socket was shut down.
func (r *uringBatchReader) reap() error {
	head := atomic.LoadUint32(r.cqHead)
	tail := atomic.LoadUint32(r.cqTail)
	provided := false
	var reapErr error
	for ; head != tail; head++ {
		cqe := (*uringCQE)(unsafe.Add(r.cqes, uintptr(head&r.cqMask)*unsafe.Sizeof(uringCQE{})))
		if cqe.userData != uringRecvTag {
			continue // the cancel's own completion
		}
		if cqe.flags&cqeFMore == 0 {
			r.armed = false
		}
		if cqe.flags&cqeFBuffer != 0 {
			bid := uint16(cqe.flags >> cqeBufferShift)
			// buffer: recvmsg_out | cmsg room (r.control) | payload
			payloadAt := uringRecvOutSize + r.control
			if int(cqe.res) >= payloadAt {
				data := r.slab[int(bid)*r.bufSize : int(bid)*r.bufSize+int(cqe.res)]
				controlLen := int(*(*uint32)(unsafe.Pointer(&data[4])))
				payloadLen := int(*(*uint32)(unsafe.Pointer(&data[8])))
				msgFlags := *(*uint32)(unsafe.Pointer(&data[12]))
				if msgFlags&unix.MSG_TRUNC == 0 && payloadAt+payloadLen <= len(data) {
					if payloadLen == 0 && r.closed.Load() {
						r.eof = true
					} else {
						payload := data[payloadAt : payloadAt+payloadLen]
						segment := 0
						if r.gro && controlLen > 0 && controlLen <= r.control {
							segment = groSegmentSize(data[uringRecvOutSize : uringRecvOutSize+controlLen])
						}
						if segment <= 0 {
							segment = len(payload)
						}
						for len(payload) > 0 {
							piece := payload[:min(segment, len(payload))]
							payload = payload[len(piece):]
							buffer := r.options.NewPacketBuffer()
							if len(piece) <= buffer.FreeLen() {
								copy(buffer.Extend(len(piece)), piece)
								r.options.PostReturn(buffer)
								r.pending = append(r.pending, buffer)
							} else {
								buffer.Release()
							}
						}
					}
				}
			}
			r.provide(bid)
			provided = true
			continue
		}
		switch {
		case cqe.res == 0, cqe.res == -int32(unix.ECANCELED):
			r.eof = true
		case cqe.res == -int32(unix.ENOBUFS):
			// every ring buffer was in use; they are back now, re-arm
		case cqe.res == -int32(unix.EMSGSIZE):
			// an ICMP "fragmentation needed" reported on the socket, not a
			// read failure (packet_mtu.go); re-arm if the receive ended
		case cqe.res < 0:
			if reapErr == nil {
				reapErr = os.NewSyscallError("io_uring recvmsg", syscall.Errno(-cqe.res))
			}
		}
	}
	atomic.StoreUint32(r.cqHead, head)
	if provided {
		r.publishBuffers()
	}
	return reapErr
}

func (r *uringBatchReader) WaitReadConnectedPackets() (buffers []*buf.Buffer, destination M.Socksaddr, err error) {
	for {
		if r.fallback != nil {
			// outside access: shutdown must not wait for a netpoller read
			return r.fallback.WaitReadConnectedPackets()
		}
		var retry bool
		buffers, destination, err, retry = r.waitRing()
		if !retry {
			return
		}
	}
}

// startFallback switches this session to the recvmmsg reader after its ring
// could not be set up (UDP_GRO, if on, stays on: the GRO reader takes over).
// It reports false when there is none to switch to.
func (r *uringBatchReader) startFallback() bool {
	var fallback N.ConnectedPacketBatchReadWaiter
	if r.gro {
		fallback = newGROBatchReader(r.rawConn)
	}
	if fallback == nil {
		fallback = newKeptBatchReader(r.rawConn)
	}
	if fallback == nil {
		return false
	}
	fallback.InitializeReadWaiter(r.options)
	r.fallback = fallback
	return true
}

func (r *uringBatchReader) waitRing() (buffers []*buf.Buffer, destination M.Socksaddr, err error, retry bool) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.ringFD < 0 {
		if r.closed.Load() {
			r.unlockThread()
			return nil, M.Socksaddr{}, io.EOF, false
		}
		// The receive task_work runs on the thread that armed it; the
		// blocking variant keeps the reader on that thread.
		if !udpIOUringNetpoll {
			runtime.LockOSThread()
			r.locked = true
		}
		if err = r.setup(); err != nil {
			closed := r.closed.Load()
			r.Close()
			if !closed && r.startFallback() {
				return nil, M.Socksaddr{}, nil, true
			}
			return nil, M.Socksaddr{}, err, false
		}
	}
	for {
		if err = r.reap(); err != nil {
			r.Close()
			return nil, M.Socksaddr{}, err, false
		}
		if len(r.pending) > 0 {
			count := min(len(r.pending), r.options.BatchSize)
			buffers = make([]*buf.Buffer, count)
			copy(buffers, r.pending[:count])
			r.pending = append(r.pending[:0], r.pending[count:]...)
			return buffers, r.destination, nil, false
		}
		if r.eof || r.closed.Load() {
			r.Close()
			return nil, M.Socksaddr{}, io.EOF, false
		}
		if !r.armed {
			r.arm()
		}
		if err = r.enter(true); err != nil {
			r.Close()
			return nil, M.Socksaddr{}, err, false
		}
	}
}

// Close releases the ring and undoes the thread lock. It runs on the reading
// goroutine with access held (after EOF or an error).
func (r *uringBatchReader) Close() {
	r.release()
	r.unlockThread()
}

func (r *uringBatchReader) unlockThread() {
	if r.locked {
		r.locked = false
		runtime.UnlockOSThread()
	}
}

// release frees the ring, its memory and pending buffers; access is held.
func (r *uringBatchReader) release() {
	if r.ringFile != nil {
		_ = r.ringFile.Close()
		r.ringFile = nil
		r.ringRaw = nil
		r.ringFD = -1
	} else if r.ringFD >= 0 {
		_ = unix.Close(r.ringFD)
		r.ringFD = -1
	}
	if r.ringMem != nil {
		_ = unix.Munmap(r.ringMem)
		r.ringMem = nil
	}
	if r.sqesMem != nil {
		_ = unix.Munmap(r.sqesMem)
		r.sqesMem = nil
	}
	if r.bufRing != nil {
		_ = unix.Munmap(r.bufRing)
		r.bufRing = nil
	}
	buf.ReleaseMulti(r.pending)
	r.pending = nil
	r.closed.Store(true)
}

func (r *uringBatchReader) Upstream() any {
	return r.rawConn
}
