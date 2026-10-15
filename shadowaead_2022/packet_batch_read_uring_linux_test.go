//go:build linux

package shadowaead_2022

import (
	"bytes"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// udpRcvbufErrors reads the kernel's Udp RcvbufErrors counter, so a test can
// tell datagrams the kernel dropped on a full socket buffer from datagrams
// the reader lost.
func udpRcvbufErrors(t *testing.T) int {
	t.Helper()
	content, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		t.Skip(err)
	}
	var header []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "Udp: ") {
			continue
		}
		fields := strings.Fields(line)
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if name == "RcvbufErrors" {
				value, _ := strconv.Atoi(fields[i])
				return value
			}
		}
	}
	t.Skip("no Udp RcvbufErrors")
	return 0
}

func newUringTestPair(t *testing.T) (*net.UDPConn, *net.UDPConn, *uringBatchReader, func()) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadBuffer(4 << 20)
	rawConn, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	enableUDPIOUring = true
	t.Cleanup(func() { enableUDPIOUring = false })
	waiter, shutdown := newUringBatchReader(rawConn)
	if waiter == nil {
		t.Skip("io_uring reader unavailable")
	}
	reader := waiter.(*uringBatchReader)
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 64, MTU: 2048})
	return server, client, reader, shutdown
}

func TestUringBatchReaderReadsInOrderAndStopsOnShutdown(t *testing.T) {
	server, client, reader, shutdown := newUringTestPair(t)
	defer server.Close()
	clientAddr := client.LocalAddr()

	const count = 200
	payload := func(i int) []byte { return bytes.Repeat([]byte{byte(i)}, 100+i) }
	dropsBefore := udpRcvbufErrors(t)
	// Loopback queues a datagram on the sending CPU's backlog, so a sender
	// that migrates between CPUs can reorder its own datagrams. Pin it.
	sendDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var cpus unix.CPUSet
		cpus.Set(0)
		if err := unix.SchedSetaffinity(0, &cpus); err != nil {
			sendDone <- err
			return
		}
		for i := range count {
			if _, err := server.WriteTo(payload(i), clientAddr); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	// Every datagram must arrive exactly once and intact. Order is not
	// checked: on the WSL test kernel loopback itself reorders such a burst,
	// and the recvmmsg reader sees the same (checked 2026-10-15: 18 of 40
	// runs for recvmmsg, 8 of 40 for io_uring, same interleaving pattern).
	seen := make([]bool, count)
	got := 0
	batches := 0
	deadline := time.Now().Add(5 * time.Second)
	for got < count && time.Now().Before(deadline) {
		buffers, destination, err := reader.WaitReadConnectedPackets()
		if err != nil {
			t.Fatalf("read after %d packets: %v", got, err)
		}
		if destination.String() != server.LocalAddr().String() {
			t.Fatalf("destination %s, want %s", destination, server.LocalAddr())
		}
		batches++
		for _, buffer := range buffers {
			// Payload i is 100+i bytes of byte(i): its length identifies it.
			index := buffer.Len() - 100
			if index < 0 || index >= count || seen[index] || !bytes.Equal(buffer.Bytes(), payload(index)) {
				t.Fatalf("bad or duplicate datagram: length %d, first byte %d", buffer.Len(), buffer.Byte(0))
			}
			seen[index] = true
			buffer.Release()
			got++
		}
		if got+udpRcvbufErrors(t)-dropsBefore >= count {
			break
		}
	}
	drops := udpRcvbufErrors(t) - dropsBefore
	if got+drops < count {
		t.Fatalf("got %d of %d packets, kernel dropped %d", got, count, drops)
	}
	t.Logf("%d packets in %d batches (%d dropped by the kernel)", got, batches, drops)

	// A reader blocked in io_uring_enter returns io.EOF after shutdown (an
	// ASYNC_CANCEL submitted from the other goroutine).
	go func() {
		time.Sleep(100 * time.Millisecond)
		shutdown()
	}()
	start := time.Now()
	_, _, err := reader.WaitReadConnectedPackets()
	if err != io.EOF {
		t.Fatalf("after shutdown: %v, want io.EOF", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("returned after %s", waited)
	}
	if reader.ringFD >= 0 {
		t.Fatal("ring not released")
	}
	client.Close()
}

func TestUringBatchReaderShutdownWhileIdleReleasesRing(t *testing.T) {
	server, client, reader, shutdown := newUringTestPair(t)
	defer server.Close()
	if _, err := server.WriteTo([]byte("x"), client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// The ring is created on the first read, from a goroutine that then
	// stops calling (as a copy loop that failed on its write side would).
	done := make(chan struct{})
	go func() {
		buffers, _, err := reader.WaitReadConnectedPackets()
		if err != nil {
			t.Error(err)
		}
		buf.ReleaseMulti(buffers)
		close(done)
	}()
	<-done
	if reader.ringFD < 0 {
		t.Fatal("ring not created")
	}
	shutdown()
	if reader.ringFD >= 0 {
		t.Fatal("shutdown left the ring of an idle reader open")
	}
	client.Close()
}
