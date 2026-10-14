//go:build linux

package shadowaead_2022

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// sendSegmented sends packets (all the size of the first, the last may be
// shorter) as one UDP_SEGMENT message, the shape a GRO socket receives
// whole on loopback.
func sendSegmented(t *testing.T, server *net.UDPConn, to *net.UDPAddr, packets [][]byte) {
	t.Helper()
	var train []byte
	for _, packet := range packets {
		train = append(train, packet...)
	}
	oob := make([]byte, unix.CmsgSpace(2))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(len(packets[0])))
	if _, _, err := server.WriteMsgUDP(train, oob, to); err != nil {
		t.Fatal(err)
	}
}

func udpGROValue(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var getErr error
	_ = rawConn.Control(func(fd uintptr) {
		value, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
	})
	if getErr != nil {
		t.Fatal(getErr)
	}
	return value
}

func newTestPayloads(sizes ...int) [][]byte {
	payloads := make([][]byte, len(sizes))
	for index, size := range sizes {
		payloads[index] = make([]byte, size)
		_, _ = rand.Read(payloads[index])
	}
	return payloads
}

// UDP_GRO is switched on by the first batch read, not before; a coalesced
// train then comes back in fewer recvmmsg entries than packets, split into
// its packets, each opened, in order, followed by a plain datagram.
func TestClientPacketBatchReadGRO(t *testing.T) {
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()
	waiter, created := conn.CreatePacketBatchReadWaiter()
	if !created {
		t.Fatal("batch read waiter not created")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 32, RearHeadroom: 16, BatchSize: 64})
	if udpGROValue(t, client) != 0 {
		t.Fatal("UDP_GRO on before the first batch read")
	}

	source := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	payloads := newTestPayloads(1200, 1200, 1200, 1200, 1200, 1200, 500, 300)
	var packets [][]byte
	for index, payload := range payloads {
		packets = append(packets, newTestServerPacket(t, conn, 0x1122334455667788, uint64(index), source, payload))
	}

	type result struct {
		buffers      []*buf.Buffer
		destinations []M.Socksaddr
		entries      int // recvmmsg entries behind this batch
		err          error
	}
	results := make(chan result, 8)
	go func() {
		for {
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffers, destinations, err := waiter.WaitReadPackets()
			entries := -1
			if gro, isGRO := waiter.(*clientPacketBatchReadWaiter).gro.(*groBatchReader); isGRO {
				entries = gro.lastN
			}
			results <- result{buffers, destinations, entries, err}
			if err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !conn.gro.on.Load() {
		if time.Now().After(deadline) {
			t.Fatal("UDP_GRO not switched on by the batch read")
		}
		time.Sleep(time.Millisecond)
	}
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	sendSegmented(t, server, clientAddr, packets[:7])
	if _, err := server.WriteToUDP(packets[7], clientAddr); err != nil {
		t.Fatal(err)
	}

	var got [][]byte
	firstBatch, firstEntries := -1, -1
	for len(got) < len(payloads) {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if firstBatch < 0 {
			firstBatch, firstEntries = len(r.buffers), r.entries
		}
		for index, buffer := range r.buffers {
			if r.destinations[index] != source {
				t.Fatalf("destination %v, want %v", r.destinations[index], source)
			}
			if buffer.Start() < 32 || buffer.FreeLen() < 16 {
				t.Fatalf("headroom lost: start %d, free %d", buffer.Start(), buffer.FreeLen())
			}
			got = append(got, append([]byte(nil), buffer.Bytes()...))
		}
		buf.ReleaseMulti(r.buffers)
	}
	if udpGROValue(t, client) != 1 {
		t.Fatal("UDP_GRO not on")
	}
	if firstEntries < 0 {
		t.Fatal("batch reads did not use the GRO reader")
	}
	// The kernel may hand a train up as one or a few coalesced entries (on
	// WSL2's loopback 1-3); either way fewer entries than packets.
	if firstEntries >= firstBatch {
		t.Fatalf("first batch: %d packets from %d entries, nothing coalesced", firstBatch, firstEntries)
	}
	for index := range payloads {
		if !bytes.Equal(got[index], payloads[index]) {
			t.Fatalf("packet %d: payload mismatch", index)
		}
	}
}

// A single-datagram read turns UDP_GRO off before reading, so trains sent
// afterwards reach it as separate datagrams again.
func TestClientPacketGROLeftBySingleRead(t *testing.T) {
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()
	rawConn, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if newGROBatchReader(conn, rawConn, N.ReadWaitOptions{}) == nil {
		t.Fatal("UDP_GRO refused")
	}
	if udpGROValue(t, client) != 1 {
		t.Fatal("UDP_GRO not on")
	}

	source := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	payloads := newTestPayloads(100, 1200, 1200, 700)
	var packets [][]byte
	for index, payload := range payloads {
		packets = append(packets, newTestServerPacket(t, conn, 9, uint64(index), source, payload))
	}
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	if _, err := server.WriteToUDP(packets[0], clientAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	readOne := func(index int) {
		t.Helper()
		buffer := buf.NewPacket()
		defer buffer.Release()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
		if destination != source || !bytes.Equal(buffer.Bytes(), payloads[index]) {
			t.Fatalf("packet %d: wrong content", index)
		}
	}
	readOne(0)
	if udpGROValue(t, client) != 0 || conn.gro.on.Load() {
		t.Fatal("single read left UDP_GRO on")
	}
	sendSegmented(t, server, clientAddr, packets[1:])
	for index := 1; index < len(payloads); index++ {
		readOne(index)
	}
}

func TestGROSegmentSize(t *testing.T) {
	if size := groSegmentSize(nil); size != 0 {
		t.Fatalf("no cmsg: %d", size)
	}
	oob := make([]byte, unix.CmsgSpace(4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_GRO
	header.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0):], 1377)
	if size := groSegmentSize(oob); size != 1377 {
		t.Fatalf("segment size %d, want 1377", size)
	}
}
