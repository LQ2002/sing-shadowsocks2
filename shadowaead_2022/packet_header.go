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
