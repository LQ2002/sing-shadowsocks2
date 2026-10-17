package shadowaead_2022

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// readUint64/readUint16 return what binary.Read returns, with the same
// errors and the same bytes consumed, for every length from 0 to 11.
func TestReadUintMatchesBinaryRead(t *testing.T) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54}
	for n := 0; n <= len(data); n++ {
		var want64 uint64
		reference := bytes.NewReader(data[:n])
		wantErr := binary.Read(reference, binary.BigEndian, &want64)
		buffer := buf.As(append([]byte(nil), data[:n]...))
		got, err := readUint64(buffer)
		if err != wantErr || (err == nil && got != want64) || buffer.Len() != reference.Len() {
			t.Fatalf("uint64 len %d: got %x/%v/%d left, want %x/%v/%d left", n, got, err, buffer.Len(), want64, wantErr, reference.Len())
		}

		var want16 uint16
		reference = bytes.NewReader(data[:n])
		wantErr = binary.Read(reference, binary.BigEndian, &want16)
		buffer = buf.As(append([]byte(nil), data[:n]...))
		got16, err := readUint16(buffer)
		if err != wantErr || (err == nil && got16 != want16) || buffer.Len() != reference.Len() {
			t.Fatalf("uint16 len %d: got %x/%v/%d left, want %x/%v/%d left", n, got16, err, buffer.Len(), want16, wantErr, reference.Len())
		}
	}
}

func BenchmarkClientReadPacketHeader(b *testing.B) {
	data := make([]byte, 64)
	b.Run("binary.Read", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buffer := buf.As(data)
			var x, y uint64
			_ = binary.Read(buffer, binary.BigEndian, &x)
			_ = binary.Read(buffer, binary.BigEndian, &y)
		}
	})
	b.Run("readUint64", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buffer := buf.As(data)
			_, _ = readUint64(buffer)
			_, _ = readUint64(buffer)
		}
	})
}

// writeUint64/writeUint16 produce the bytes binary.Write produces, after
// whatever the buffer already holds.
func TestWriteUintMatchesBinaryWrite(t *testing.T) {
	for _, value := range []uint64{0, 1, 0x0123456789abcdef, ^uint64(0)} {
		want := buf.NewSize(32)
		_, _ = want.Write([]byte{0xaa})
		if err := binary.Write(want, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(want, binary.BigEndian, uint16(value)); err != nil {
			t.Fatal(err)
		}
		got := buf.NewSize(32)
		_, _ = got.Write([]byte{0xaa})
		writeUint64(got, value)
		writeUint16(got, uint16(value))
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("%x: got %x, want %x", value, got.Bytes(), want.Bytes())
		}
		got.Release()
		want.Release()
	}
}

func BenchmarkClientWritePacketHeader(b *testing.B) {
	b.Run("binary.Write", func(b *testing.B) {
		b.ReportAllocs()
		buffer := buf.NewSize(64)
		defer buffer.Release()
		for i := 0; i < b.N; i++ {
			buffer.Reset()
			_ = binary.Write(buffer, binary.BigEndian, uint64(i))
			_ = binary.Write(buffer, binary.BigEndian, uint64(i))
			_ = binary.Write(buffer, binary.BigEndian, uint16(i))
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		buffer := buf.NewSize(64)
		defer buffer.Release()
		for i := 0; i < b.N; i++ {
			buffer.Reset()
			writeUint64(buffer, uint64(i))
			writeUint64(buffer, uint64(i))
			writeUint16(buffer, uint16(i))
		}
	})
}

// readSocksaddr must return exactly what M.SocksaddrSerializer.ReadAddrPort
// returns (address, error text, bytes consumed) for any input; the inputs
// cover every type byte, every truncation and random tails.
func TestReadSocksaddrMatchesSerializer(t *testing.T) {
	seeds := [][]byte{
		{0x01, 1, 2, 3, 4, 0x01, 0xbb},
		{0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x35},
		{0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8, 0x00, 0x35}, // IPv4-mapped
		append(append([]byte{0x03, 11}, "example.com"...), 0x01, 0xbb),
		append(append([]byte{0x03, 7}, "1.2.3.4"...), 0x00, 0x50), // domain that parses as an IP
		append(append([]byte{0x03, 5}, "[::1]"...), 0x00, 0x50),
		{0x03, 0, 0x00, 0x50},
		{0x00, 1, 2},
		{0x02, 1, 2, 3, 4, 5, 6},
		{},
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		random := make([]byte, rng.Intn(40))
		rng.Read(random)
		if len(random) > 0 && rng.Intn(2) == 0 {
			random[0] = []byte{0x01, 0x03, 0x04}[rng.Intn(3)]
		}
		seeds = append(seeds, random)
	}
	for _, seed := range seeds {
		for n := 0; n <= len(seed); n++ {
			input := append(seed[:n:n], 0xee) // a trailing byte must stay unread
			want := buf.As(append([]byte(nil), input...))
			wantAddr, wantErr := M.SocksaddrSerializer.ReadAddrPort(want)
			got := buf.As(append([]byte(nil), input...))
			gotAddr, gotErr := readSocksaddr(got)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || gotAddr != wantAddr || got.Len() != want.Len() {
				t.Fatalf("input %x: got %v/%v/%d left, want %v/%v/%d left", input, gotAddr, gotErr, got.Len(), wantAddr, wantErr, want.Len())
			}
		}
	}
}

// writeSocksaddr must write exactly what the Serializer writes, including
// when the buffer runs out of room.
func TestWriteSocksaddrMatchesSerializer(t *testing.T) {
	long := strings.Repeat("a", 255)
	addresses := []M.Socksaddr{
		M.ParseSocksaddr("1.2.3.4:443"),
		M.ParseSocksaddr("[2001:db8::1]:53"),
		{Addr: netip.MustParseAddr("::ffff:8.8.8.8"), Port: 53},
		{Fqdn: "example.com", Port: 443},
		{Fqdn: long, Port: 1},
		{Fqdn: long + "a", Port: 1},
		{Fqdn: "x", Addr: netip.MustParseAddr("9.9.9.9"), Port: 9},
		{},
		{Port: 80},
	}
	for _, address := range addresses {
		for capacity := 0; capacity <= 270; capacity++ {
			want := buf.NewSize(capacity)
			wantErr := M.SocksaddrSerializer.WriteAddrPort(want, address)
			got := buf.NewSize(capacity)
			gotErr := writeSocksaddr(got, address)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !bytes.Equal(got.Bytes(), want.Bytes()) {
				t.Fatalf("%v cap %d: got %x/%v, want %x/%v", address, capacity, got.Bytes(), gotErr, want.Bytes(), wantErr)
			}
			got.Release()
			want.Release()
		}
	}
}

func BenchmarkSocksaddr(b *testing.B) {
	address := M.ParseSocksaddr("1.2.3.4:443")
	b.Run("Serializer", func(b *testing.B) {
		b.ReportAllocs()
		buffer := buf.NewSize(64)
		defer buffer.Release()
		for i := 0; i < b.N; i++ {
			buffer.Reset()
			_ = M.SocksaddrSerializer.WriteAddrPort(buffer, address)
			_, _ = M.SocksaddrSerializer.ReadAddrPort(buffer)
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		buffer := buf.NewSize(64)
		defer buffer.Release()
		for i := 0; i < b.N; i++ {
			buffer.Reset()
			_ = writeSocksaddr(buffer, address)
			_, _ = readSocksaddr(buffer)
		}
	})
}
