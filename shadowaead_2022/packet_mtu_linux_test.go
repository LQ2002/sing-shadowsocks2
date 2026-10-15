//go:build linux

package shadowaead_2022

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

// newDFTestPair is newTestBatchPair with DF set on the client socket, as
// sing-box dials the server. A datagram above the loopback MTU (or the
// 65507-byte UDP maximum) is what does not fit.
func newDFTestPair(t *testing.T) (*net.UDPConn, *net.UDPConn, *clientPacketConn) {
	t.Helper()
	server, client, conn := newTestBatchPair(t)
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, client, conn
}

// receivedSizes returns the sizes of the datagrams queued on server.
func receivedSizes(t *testing.T, server *net.UDPConn) []int {
	t.Helper()
	var sizes []int
	data := make([]byte, 65536)
	for {
		_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := server.ReadFromUDP(data)
		if err != nil {
			return sizes
		}
		sizes = append(sizes, n)
	}
}

const oversizedPayload = 65500 // sealed: above the 65507-byte UDP maximum

func TestClientPacketConnDropsOversized(t *testing.T) {
	server, client, conn := newDFTestPair(t)
	defer server.Close()
	defer client.Close()
	destination := M.ParseSocksaddrHostPort("1.2.3.4", 443)

	if err := conn.WritePacket(newTestPayloadBuffer(conn, make([]byte, oversizedPayload)), destination); err != nil {
		t.Fatalf("oversized write: %v, want it dropped", err)
	}
	raw, _ := client.SyscallConn()
	if limit, want := int(conn.pathMTU.limit.Load()), socketMaxDatagram(raw); limit == 0 || limit != want {
		t.Fatalf("path limit %d, want the socket's IP_MTU - 28 = %d", limit, want)
	}
	if err := conn.WritePacket(newTestPayloadBuffer(conn, make([]byte, 1200)), destination); err != nil {
		t.Fatal(err)
	}
	// now filtered before the send
	if err := conn.WritePacket(newTestPayloadBuffer(conn, make([]byte, oversizedPayload)), destination); err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(newTestPayloadBuffer(conn, make([]byte, 1300)), destination); err != nil {
		t.Fatal(err)
	}
	sizes := receivedSizes(t, server)
	if len(sizes) != 2 || sizes[0] >= 2000 || sizes[1] <= sizes[0] {
		t.Fatalf("server got %v, want the two small datagrams in order", sizes)
	}
}

func TestClientPacketBatchWriterDropsOversized(t *testing.T) {
	server, client, conn := newDFTestPair(t)
	defer server.Close()
	defer client.Close()
	writer, created := conn.CreatePacketBatchWriter()
	if !created {
		t.Fatal("batch writer not created")
	}
	destination := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	batch := func(sizes ...int) error {
		buffers := make([]*buf.Buffer, len(sizes))
		destinations := make([]M.Socksaddr, len(sizes))
		for index, size := range sizes {
			buffers[index] = newTestPayloadBuffer(conn, make([]byte, size))
			destinations[index] = destination
		}
		return writer.WritePacketBatch(buffers, destinations)
	}
	// The oversized one ends this batch: 1100 goes out, 1110 is lost once.
	if err := batch(1100, oversizedPayload, 1110); err != nil {
		t.Fatalf("batch with an oversized datagram: %v, want it dropped", err)
	}
	// Known now: filtered out, the rest of the batch goes out.
	if err := batch(oversizedPayload, 1120, 1130); err != nil {
		t.Fatal(err)
	}
	if err := batch(oversizedPayload); err != nil {
		t.Fatal(err)
	}
	sizes := receivedSizes(t, server)
	if len(sizes) != 3 || sizes[1] != sizes[0]+20 || sizes[2] != sizes[0]+30 {
		t.Fatalf("server got %v, want the 1100, 1120 and 1130 payloads", sizes)
	}
}
