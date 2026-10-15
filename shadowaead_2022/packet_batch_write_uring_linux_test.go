//go:build linux

package shadowaead_2022

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func uringWritePayload(i int) []byte {
	size := 1200
	if i%7 == 6 {
		size = 300 + i
	}
	payload := bytes.Repeat([]byte{byte(i)}, size)
	payload[0] = byte(i)
	payload[1] = byte(i >> 8)
	return payload
}

func TestUringConnectedWriterDeliversBatches(t *testing.T) {
	enableUDPIOUringSend = true
	defer func() { enableUDPIOUringSend = false }()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	_ = receiver.SetReadBuffer(8 << 20)
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	rawConn, _ := sender.SyscallConn()
	writer := newUringConnectedWriter(rawConn, false)
	if writer == nil {
		t.Skip("io_uring writer unavailable")
	}
	defer writer.Close()
	const count = 400
	for start := 0; start < count; start += 40 {
		var buffers []*buf.Buffer
		for i := start; i < start+40; i++ {
			buffers = append(buffers, buf.As(uringWritePayload(i)).ToOwned())
		}
		if err = writer.WriteConnectedPacketBatch(buffers); err != nil {
			t.Fatal(err)
		}
	}
	seen := make([]bool, count)
	readBuffer := make([]byte, 65536)
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	for got := 0; got < count; got++ {
		n, err := receiver.Read(readBuffer)
		if err != nil {
			t.Fatalf("after %d datagrams: %v", got, err)
		}
		i := int(readBuffer[0]) | int(readBuffer[1])<<8
		if i >= count || seen[i] || !bytes.Equal(readBuffer[:n], uringWritePayload(i)) {
			t.Fatalf("bad or duplicate datagram %d (length %d)", i, n)
		}
		seen[i] = true
	}
	if writer.noGSO {
		t.Log("GSO refused; sent one by one")
	}
	writer.Close()
	if err = writer.WriteConnectedPacketBatch([]*buf.Buffer{buf.As([]byte("x")).ToOwned()}); err != net.ErrClosed {
		t.Fatalf("write after Close: %v", err)
	}
}
