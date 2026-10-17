package shadowaead_2022

import (
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common/buf"
)

// readUint64 and readUint16 take a big-endian field off the front of
// buffer without binary.Read's reflection and allocation. Errors match
// binary.Read: io.EOF when nothing is left, io.ErrUnexpectedEOF when the
// field is cut short (the bytes that are there are consumed, as
// binary.Read's io.ReadFull consumes them).

func readUint64(buffer *buf.Buffer) (uint64, error) {
	if buffer.Len() < 8 {
		return 0, shortRead(buffer)
	}
	value := binary.BigEndian.Uint64(buffer.To(8))
	buffer.Advance(8)
	return value, nil
}

func readUint16(buffer *buf.Buffer) (uint16, error) {
	if buffer.Len() < 2 {
		return 0, shortRead(buffer)
	}
	value := binary.BigEndian.Uint16(buffer.To(2))
	buffer.Advance(2)
	return value, nil
}

func shortRead(buffer *buf.Buffer) error {
	if buffer.IsEmpty() {
		return io.EOF
	}
	buffer.Advance(buffer.Len())
	return io.ErrUnexpectedEOF
}

// writeUint64 and writeUint16 append a big-endian field without
// binary.Write, which boxes the value into an interface and allocates a
// scratch slice per call (encoding/binary.encodeFast was ~0.7% of sing-box
// CPU in a paced UDP upload on the phone, 2026-10-17). They panic like
// common.Must(binary.Write(...)) did when the buffer has no room.

func writeUint64(buffer *buf.Buffer, value uint64) {
	binary.BigEndian.PutUint64(buffer.Extend(8), value)
}

func writeUint16(buffer *buf.Buffer, value uint16) {
	binary.BigEndian.PutUint16(buffer.Extend(2), value)
}
