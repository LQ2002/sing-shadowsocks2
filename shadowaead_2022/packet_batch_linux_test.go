//go:build linux

package shadowaead_2022

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing-shadowsocks2/internal/shadowio"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func newTestClientConn(t *testing.T, conn net.Conn) *clientPacketConn {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	method, err := NewMethod(context.Background(), "2022-blake3-aes-256-gcm", C.MethodOptions{Password: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		t.Fatal(err)
	}
	return method.(*Method).DialPacketConn(conn).(*clientPacketConn)
}

func newTestPayloadBuffer(conn *clientPacketConn, payload []byte) *buf.Buffer {
	buffer := buf.NewSize(conn.FrontHeadroom() + len(payload) + conn.RearHeadroom())
	buffer.Resize(conn.FrontHeadroom(), 0)
	copy(buffer.Extend(len(payload)), payload)
	return buffer
}

// Every datagram written by a batch must be an ordinary, independently
// decryptable client packet: same session, consecutive packet IDs, intact
// destination and payload. Same-sized packets followed by a shorter tail is
// the shape that sing's batch writer sends as one UDP GSO message.
func TestClientPacketBatchWriter(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn := newTestClientConn(t, client)

	writer, created := conn.CreatePacketBatchWriter()
	if !created {
		t.Fatal("batch writer not created for a connected UDP socket")
	}

	destination := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	sizes := []int{1250, 1250, 1250, 1250, 1250, 1250, 1250, 700}
	payloads := make([][]byte, len(sizes))
	buffers := make([]*buf.Buffer, len(sizes))
	destinations := make([]M.Socksaddr, len(sizes))
	for index, size := range sizes {
		payloads[index] = make([]byte, size)
		_, _ = rand.Read(payloads[index])
		buffers[index] = newTestPayloadBuffer(conn, payloads[index])
		destinations[index] = destination
	}
	err = writer.WritePacketBatch(buffers, destinations)
	if err != nil {
		t.Fatal(err)
	}

	headerBlock, err := aes.NewCipher(conn.method.pskList[len(conn.method.pskList)-1])
	if err != nil {
		t.Fatal(err)
	}
	overhead := aes.BlockSize + 1 + 8 + 2 + M.SocksaddrSerializer.AddrPortLen(destination) + shadowio.Overhead
	readBuffer := make([]byte, 65535)
	for index, payload := range payloads {
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := server.Read(readBuffer)
		if err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
		packet := readBuffer[:n]
		if n != len(payload)+overhead {
			t.Fatalf("packet %d: length %d, want %d", index, n, len(payload)+overhead)
		}
		packetHeader := make([]byte, aes.BlockSize)
		headerBlock.Decrypt(packetHeader, packet[:aes.BlockSize])
		if sessionID := binary.BigEndian.Uint64(packetHeader[:8]); sessionID != conn.session.sessionId {
			t.Fatalf("packet %d: session %x, want %x", index, sessionID, conn.session.sessionId)
		}
		if packetID := binary.BigEndian.Uint64(packetHeader[8:]); packetID != uint64(index) {
			t.Fatalf("packet %d: packet id %d", index, packetID)
		}
		plain, err := conn.session.cipher.Open(nil, packetHeader[4:16], packet[aes.BlockSize:], nil)
		if err != nil {
			t.Fatalf("packet %d: open: %v", index, err)
		}
		if plain[0] != HeaderTypeClient {
			t.Fatalf("packet %d: header type %d", index, plain[0])
		}
		if paddingLen := binary.BigEndian.Uint16(plain[9:11]); paddingLen != 0 {
			t.Fatalf("packet %d: padding %d", index, paddingLen)
		}
		reader := bytes.NewReader(plain[11:])
		parsed, err := M.SocksaddrSerializer.ReadAddrPort(reader)
		if err != nil || parsed != destination {
			t.Fatalf("packet %d: destination %v (%v)", index, parsed, err)
		}
		rest := plain[len(plain)-reader.Len():]
		if !bytes.Equal(rest, payload) {
			t.Fatalf("packet %d: payload mismatch", index)
		}
	}
}

// Without a connected socket there is nothing to batch into; packet copies
// must fall back to WritePacket.
func TestClientPacketBatchWriterUnconnected(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	conn := newTestClientConn(t, socket)
	if _, created := conn.CreatePacketBatchWriter(); created {
		t.Fatal("batch writer created for an unconnected socket")
	}
}
