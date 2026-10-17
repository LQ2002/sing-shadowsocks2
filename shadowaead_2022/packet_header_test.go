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
