package shadowaead_2022

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/sagernet/sing/common/buf"
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
