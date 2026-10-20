//go:build linux

package shadowaead_2022

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// uringWaker is the helper ring behind SS2_UDP_IOURING_DEFER: a
// SINGLE_ISSUER ring accepts submissions only from its own thread, so a
// closing goroutine cannot submit the reader's cancel. It submits an
// IORING_OP_MSG_RING on this shared ring instead, which posts a uringWakeTag
// completion to the reader's ring and so ends its io_uring_enter(GETEVENTS).
// One ring serves the process; access serializes the closers (a close is
// rare next to the datagrams).
var uringWaker struct {
	once   sync.Once
	ok     bool
	access sync.Mutex
	ring   uringBatchReader // only the ring fields are used
}

// uringWakerAvailable sets the helper ring up on first use and reports whether it
// works; without it readers stay non-deferred.
func uringWakerAvailable() bool {
	uringWaker.once.Do(func() {
		ring := &uringWaker.ring
		ring.ringFD = -1
		var params uringParams
		params.flags = setupCQSize
		params.cqEntries = uringCQEntries
		fd, _, errno := unix.RawSyscall(sysIOURingSetup, uringSQEntries, uintptr(unsafe.Pointer(&params)), 0)
		if errno != 0 {
			return
		}
		ring.ringFD = int(fd)
		if params.features&featSingleMmap == 0 {
			ring.release()
			return
		}
		sqSize := params.sqOff.array + params.sqEntries*4
		cqSize := params.cqOff.cqes + params.cqEntries*uint32(unsafe.Sizeof(uringCQE{}))
		ringMem, err := unix.Mmap(ring.ringFD, offSQRing, int(max(sqSize, cqSize)), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			ring.release()
			return
		}
		ring.ringMem = ringMem
		sqesMem, err := unix.Mmap(ring.ringFD, offSQEs, int(params.sqEntries)*int(unsafe.Sizeof(uringSQE{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			ring.release()
			return
		}
		ring.sqesMem = sqesMem
		base := unsafe.Pointer(&ringMem[0])
		ring.sqHead = (*uint32)(unsafe.Add(base, params.sqOff.head))
		ring.sqTail = (*uint32)(unsafe.Add(base, params.sqOff.tail))
		ring.sqMask = *(*uint32)(unsafe.Add(base, params.sqOff.ringMask))
		ring.sqArray = unsafe.Add(base, params.sqOff.array)
		ring.sqes = unsafe.Pointer(&sqesMem[0])
		ring.cqHead = (*uint32)(unsafe.Add(base, params.cqOff.head))
		ring.cqTail = (*uint32)(unsafe.Add(base, params.cqOff.tail))
		ring.cqMask = *(*uint32)(unsafe.Add(base, params.cqOff.ringMask))
		ring.cqes = unsafe.Add(base, params.cqOff.cqes)
		uringWaker.ok = true
	})
	return uringWaker.ok
}

// uringWake posts a uringWakeTag completion to target (a ring fd that stays
// open for the call: the caller holds the reader's access) and waits for the
// MSG_RING's own completion, so the wake is delivered when it returns.
func uringWake(target int) {
	uringWaker.access.Lock()
	defer uringWaker.access.Unlock()
	ring := &uringWaker.ring
	ring.pushSQE(uringSQE{
		opcode:   opMsgRing,
		fd:       int32(target),
		off:      uringWakeTag, // user_data of the completion posted to target
		userData: uringWakeTag,
	})
	for {
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(ring.ringFD), 1, 1, enterGetEvents, 0, 0)
		if errno != unix.EINTR {
			break
		}
	}
	// Drop the MSG_RING completion (its result does not matter: a target
	// that already went away needs no wake).
	atomic.StoreUint32(ring.cqHead, atomic.LoadUint32(ring.cqTail))
}
