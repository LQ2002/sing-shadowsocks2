//go:build linux

package shadowaead_2022

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// sip022Overhead is what newTestServerPacket adds around the payload for an
// IPv4 source: header block, type, timestamp, client session ID, padding
// length, address (type, IPv4, port) and the AEAD tag.
const sip022Overhead = 16 + 1 + 8 + 8 + 2 + 1 + 4 + 2 + 16

// sendGSO sends the packets in one sendmsg with UDP_SEGMENT, so the kernel
// queues them on the loopback receiver as one merged skb (when the receiver
// has UDP_GRO on) the way rmnet and FISA do on the phone.
func sendGSO(t *testing.T, server *net.UDPConn, to *net.UDPAddr, segment int, packets [][]byte) {
	t.Helper()
	var payload []byte
	for _, packet := range packets {
		payload = append(payload, packet...)
	}
	oob := make([]byte, unix.CmsgSpace(2))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&oob[unix.SizeofCmsghdr])) = uint16(segment)
	if _, _, err := server.WriteMsgUDP(payload, oob, to); err != nil {
		t.Fatal(err)
	}
}

// The kernel in this environment really hands a GSO send to a UDP_GRO
// socket as one message with the segment size in a cmsg; otherwise the
// reader test below would pass without exercising the split.
func TestUDPGROLoopbackMerges(t *testing.T) {
	server, client, _ := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1); err != nil {
			t.Skip("UDP_GRO unsupported:", err)
		}
	})
	sendGSO(t, server, client.LocalAddr().(*net.UDPAddr), 100, [][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 40)})
	data := make([]byte, 65536)
	oob := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := client.ReadMsgUDP(data, oob)
	if err != nil {
		t.Fatal(err)
	}
	if n != 240 || groSegmentSize(oob[:oobn]) != 100 {
		t.Fatalf("got %d bytes, segment %d; want 240 bytes, segment 100", n, groSegmentSize(oob[:oobn]))
	}
}

// Merged datagrams are cut at the segment size (last piece shorter), every
// piece is opened on its own and in order, a piece that fails to open is
// dropped, and a datagram that was not merged passes as is.
func TestGROBatchReader(t *testing.T) {
	enableUDPGRO = true
	defer func() { enableUDPGRO = false }()
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()

	waiter, created := conn.CreatePacketBatchReadWaiter()
	if !created {
		t.Fatal("batch read waiter not created")
	}
	if _, isGRO := waiter.(*clientPacketBatchReadWaiter).reader.(*groBatchReader); !isGRO {
		t.Fatal("SS2_UDP_GRO did not select the GRO reader")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 65535, BatchSize: 64})

	source := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	const segment = 1350
	var (
		want    [][]byte
		packets [][]byte
		id      uint64
	)
	seal := func(size int, broken bool) []byte {
		payload := make([]byte, size-sip022Overhead)
		_, _ = rand.Read(payload)
		packet := newTestServerPacket(t, conn, 0x1122334455667788, id, source, payload)
		id++
		if len(packet) != size {
			t.Fatalf("sealed %d bytes, want %d", len(packet), size)
		}
		if broken {
			packet[len(packet)-1] ^= 0xff
		} else {
			want = append(want, payload)
		}
		return packet
	}
	for index := 0; index < 6; index++ {
		packets = append(packets, seal(segment, index == 2))
	}
	packets = append(packets, seal(700, false))
	sendGSO(t, server, clientAddr, segment, packets)
	if _, err := server.WriteToUDP(seal(900, false), clientAddr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	var got [][]byte
	for len(got) < len(want) {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffers, destinations, err := waiter.WaitReadPackets()
		if err != nil {
			t.Fatal(err)
		}
		for index, buffer := range buffers {
			if destinations[index] != source {
				t.Fatalf("destination %v, want %v", destinations[index], source)
			}
			got = append(got, append([]byte(nil), buffer.Bytes()...))
		}
		buf.ReleaseMulti(buffers)
	}
	if len(got) != len(want) {
		t.Fatalf("%d packets, want %d", len(got), len(want))
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			t.Fatalf("packet %d: payload mismatch", index)
		}
	}
}
