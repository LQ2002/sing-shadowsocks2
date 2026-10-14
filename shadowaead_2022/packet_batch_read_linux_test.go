//go:build linux

package shadowaead_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// newTestServerPacket seals one server-to-client SIP022 packet for conn the
// way a server does: header block (server session ID, packet ID) encrypted
// with the PSK, body sealed with the server session's subkey.
func newTestServerPacket(t *testing.T, conn *clientPacketConn, serverSessionID, packetID uint64, source M.Socksaddr, payload []byte) []byte {
	t.Helper()
	psk := conn.method.pskList[len(conn.method.pskList)-1]
	header := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint64(header[:8], serverSessionID)
	binary.BigEndian.PutUint64(header[8:], packetID)
	body := bytes.NewBuffer(nil)
	body.WriteByte(HeaderTypeServer)
	_ = binary.Write(body, binary.BigEndian, uint64(time.Now().Unix()))
	_ = binary.Write(body, binary.BigEndian, conn.session.sessionId)
	_ = binary.Write(body, binary.BigEndian, uint16(0))
	if err := M.SocksaddrSerializer.WriteAddrPort(body, source); err != nil {
		t.Fatal(err)
	}
	body.Write(payload)
	aead, err := conn.method.constructor(SessionKey(psk, header[:8], conn.method.keySaltLength))
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, header[4:16], body.Bytes(), nil)
	block, err := aes.NewCipher(psk)
	if err != nil {
		t.Fatal(err)
	}
	block.Encrypt(header, header)
	return append(header, sealed...)
}

func newTestBatchPair(t *testing.T) (*net.UDPConn, *net.UDPConn, *clientPacketConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	return server, client, newTestClientConn(t, client)
}

// Everything queued on the socket comes back from one WaitReadPackets, opened
// and in order; a datagram that fails to open is dropped from the batch
// instead of failing it.
func TestClientPacketBatchReadWaiter(t *testing.T) {
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()

	waiter, created := conn.CreatePacketBatchReadWaiter()
	if !created {
		t.Fatal("batch read waiter not created for a connected UDP socket")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 65535, BatchSize: 16})

	source := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	var want [][]byte
	for index := 0; index < 8; index++ {
		payload := make([]byte, 1200+index)
		_, _ = rand.Read(payload)
		packet := newTestServerPacket(t, conn, 0x1122334455667788, uint64(index), source, payload)
		if index == 3 {
			packet[len(packet)-1] ^= 0xff // break the tag: must be dropped
		} else {
			want = append(want, payload)
		}
		if _, err := server.WriteToUDP(packet, clientAddr); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond) // let all 8 queue on the client socket

	var got [][]byte
	for len(got) < len(want) {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffers, destinations, err := waiter.WaitReadPackets()
		if err != nil {
			t.Fatal(err)
		}
		if len(buffers) != len(destinations) {
			t.Fatalf("%d buffers, %d destinations", len(buffers), len(destinations))
		}
		if len(got) == 0 && len(buffers) != len(want) {
			t.Fatalf("first batch has %d packets, want all %d queued valid ones", len(buffers), len(want))
		}
		for index, buffer := range buffers {
			if destinations[index] != source {
				t.Fatalf("destination %v, want %v", destinations[index], source)
			}
			got = append(got, append([]byte(nil), buffer.Bytes()...))
		}
		buf.ReleaseMulti(buffers)
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			t.Fatalf("packet %d: payload mismatch", index)
		}
	}
}

// A batch in which nothing opens fails with the open error, as a single read
// of that datagram did.
func TestClientPacketBatchReadWaiterAllInvalid(t *testing.T) {
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()
	waiter, created := conn.CreatePacketBatchReadWaiter()
	if !created {
		t.Fatal("batch read waiter not created")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 65535, BatchSize: 16})
	packet := newTestServerPacket(t, conn, 7, 0, M.ParseSocksaddrHostPort("1.2.3.4", 443), []byte("x"))
	packet[len(packet)-1] ^= 0xff
	if _, err := server.WriteToUDP(packet, client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := waiter.WaitReadPackets(); err == nil {
		t.Fatal("expected the open error")
	}
}

// Without a connected socket there is nothing to read in batches.
func TestClientPacketBatchReadWaiterUnconnected(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	conn := newTestClientConn(t, socket)
	if _, created := conn.CreatePacketBatchReadWaiter(); created {
		t.Fatal("batch read waiter created for an unconnected socket")
	}
}

// The batch waiter reads through keptBatchReader, which keeps the packet
// buffers recvmmsg left empty for the next read instead of releasing them,
// and frees them all when re-initialised.
func TestClientPacketBatchReadKeepsBuffers(t *testing.T) {
	server, client, conn := newTestBatchPair(t)
	defer server.Close()
	defer client.Close()
	waiter, created := conn.CreatePacketBatchReadWaiter()
	if !created {
		t.Fatal("batch read waiter not created")
	}
	kept, isKept := waiter.(*clientPacketBatchReadWaiter).reader.(*keptBatchReader)
	if !isKept {
		t.Fatalf("reader is %T, want *keptBatchReader", waiter.(*clientPacketBatchReadWaiter).reader)
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 65535, BatchSize: 16})
	source := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	var spare []*buf.Buffer
	for round := 0; round < 3; round++ {
		packet := newTestServerPacket(t, conn, 9, uint64(round), source, []byte("payload"))
		if _, err := server.WriteToUDP(packet, client.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffers, _, err := waiter.WaitReadPackets()
		if err != nil {
			t.Fatal(err)
		}
		if len(buffers) != 1 || string(buffers[0].Bytes()) != "payload" {
			t.Fatalf("round %d: got %d packets", round, len(buffers))
		}
		buf.ReleaseMulti(buffers)
		if kept.buffers[0] != nil {
			t.Fatal("slot handed to the caller was not cleared")
		}
		for index := 1; index < len(kept.buffers); index++ {
			if kept.buffers[index] == nil {
				t.Fatalf("round %d: unfilled slot %d was released", round, index)
			}
			if round > 0 && kept.buffers[index] != spare[index] {
				t.Fatalf("round %d: unfilled slot %d was replaced", round, index)
			}
		}
		spare = append(spare[:0], kept.buffers...)
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 65535, BatchSize: 16})
	for index, buffer := range kept.buffers {
		if buffer != nil {
			t.Fatalf("slot %d still held after re-initialising", index)
		}
	}
}
