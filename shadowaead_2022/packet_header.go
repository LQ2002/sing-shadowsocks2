package shadowaead_2022

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
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

// writeSocksaddr and readSocksaddr handle the per-packet SOCKS address
// (type byte, IPv4/IPv6/domain, big-endian port) for the common cases and
// hand everything else to M.SocksaddrSerializer, so results and errors are
// the Serializer's. The Serializer writes and reads the port and the type
// and length bytes with binary.Write/binary.Read: on the phone that was
// ~0.2 Mcycles per MB of UDP after the header fields above were changed
// (2026-10-17 profile of the candidate build).
//
// The fast path only runs when the whole field fits (write: free space;
// read: bytes present); a short buffer, an unknown type byte, an invalid
// address or a domain longer than 255 bytes take the Serializer path.

func writeSocksaddr(buffer *buf.Buffer, destination M.Socksaddr) error {
	addr := destination.Addr
	switch {
	case addr.Is4():
		if buffer.FreeLen() >= 7 {
			b := buffer.Extend(7)
			b[0] = 0x01
			a := addr.As4()
			copy(b[1:5], a[:])
			binary.BigEndian.PutUint16(b[5:], destination.Port)
			return nil
		}
	case addr.Is6():
		if buffer.FreeLen() >= 19 {
			b := buffer.Extend(19)
			b[0] = 0x04
			a := addr.As16()
			copy(b[1:17], a[:])
			binary.BigEndian.PutUint16(b[17:], destination.Port)
			return nil
		}
	case !addr.IsValid() && destination.Fqdn != "" && len(destination.Fqdn) <= 255:
		n := len(destination.Fqdn)
		if buffer.FreeLen() >= n+4 {
			b := buffer.Extend(n + 4)
			b[0] = 0x03
			b[1] = byte(n)
			copy(b[2:2+n], destination.Fqdn)
			binary.BigEndian.PutUint16(b[2+n:], destination.Port)
			return nil
		}
	}
	return M.SocksaddrSerializer.WriteAddrPort(buffer, destination)
}

func readSocksaddr(buffer *buf.Buffer) (M.Socksaddr, error) {
	b := buffer.Bytes()
	if len(b) > 0 {
		switch b[0] {
		case 0x01:
			if len(b) >= 7 {
				destination := M.Socksaddr{
					Addr: netip.AddrFrom4([4]byte(b[1:5])),
					Port: binary.BigEndian.Uint16(b[5:7]),
				}
				buffer.Advance(7)
				return destination, nil
			}
		case 0x04:
			if len(b) >= 19 {
				destination := M.Socksaddr{Addr: netip.AddrFrom16([16]byte(b[1:17]))}.Unwrap()
				destination.Port = binary.BigEndian.Uint16(b[17:19])
				buffer.Advance(19)
				return destination, nil
			}
		case 0x03:
			// An empty domain reads back as an invalid address, for which the
			// Serializer does not read a port; leave that case to it.
			if len(b) >= 2 && b[1] > 0 {
				n := int(b[1])
				if len(b) >= n+4 {
					destination := M.ParseSocksaddrHostPort(string(b[2:2+n]), 0)
					destination.Port = binary.BigEndian.Uint16(b[2+n : 4+n])
					buffer.Advance(n + 4)
					return destination, nil
				}
			}
		}
	}
	return M.SocksaddrSerializer.ReadAddrPort(buffer)
}
