package mitm

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// ErrNotClientHello means the bytes read were not a TLS ClientHello, so the
// connection cannot be intercepted and must be tunnelled.
var ErrNotClientHello = errors.New("mitm: not a TLS ClientHello")

// PeekedConn is a net.Conn whose first bytes have already been read but are
// replayed to the next reader, so a TLS server can consume the handshake it
// never saw arrive.
type PeekedConn struct {
	net.Conn
	buf []byte
}

// NewPeekedConn wraps c, prepending buf to whatever c yields next.
func NewPeekedConn(c net.Conn, buf []byte) *PeekedConn {
	return &PeekedConn{Conn: c, buf: buf}
}

func (p *PeekedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// PeekClientHello reads just enough of c to recover the SNI, returning the
// consumed bytes so the caller can replay them.
//
// The returned bytes are always valid even on error, so a connection that
// turns out not to be TLS can still be tunnelled without losing its prefix.
func PeekClientHello(c net.Conn) (sni string, consumed []byte, err error) {
	// TLS record header: type(1) version(2) length(2)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", hdr[:0], err
	}
	if hdr[0] != 0x16 { // not handshake
		return "", hdr, ErrNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen == 0 || recLen > 1<<14 {
		return "", hdr, ErrNotClientHello
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return "", append(hdr, body...), err
	}
	consumed = append(hdr, body...)

	name, err := sniFromHandshake(body)
	if err != nil {
		return "", consumed, err
	}
	return name, consumed, nil
}

// sniFromHandshake walks a ClientHello body to its server_name extension.
func sniFromHandshake(b []byte) (string, error) {
	// handshake header: type(1) length(3)
	if len(b) < 4 || b[0] != 0x01 {
		return "", ErrNotClientHello
	}
	i := 4

	// client_version(2) + random(32)
	if len(b) < i+34 {
		return "", ErrNotClientHello
	}
	i += 34

	// session_id
	if len(b) < i+1 {
		return "", ErrNotClientHello
	}
	i += 1 + int(b[i])

	// cipher_suites
	if len(b) < i+2 {
		return "", ErrNotClientHello
	}
	i += 2 + int(binary.BigEndian.Uint16(b[i:i+2]))

	// compression_methods
	if len(b) < i+1 {
		return "", ErrNotClientHello
	}
	i += 1 + int(b[i])

	// extensions
	if len(b) < i+2 {
		return "", ErrNotClientHello
	}
	extEnd := i + 2 + int(binary.BigEndian.Uint16(b[i:i+2]))
	i += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}

	for i+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[i : i+2])
		size := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if i+size > extEnd {
			return "", ErrNotClientHello
		}
		if typ != 0x0000 { // server_name
			i += size
			continue
		}
		ext := b[i : i+size]
		// server_name_list: list_length(2) then entries of type(1) len(2) name
		if len(ext) < 2 {
			return "", ErrNotClientHello
		}
		j := 2
		for j+3 <= len(ext) {
			nameType := ext[j]
			nameLen := int(binary.BigEndian.Uint16(ext[j+1 : j+3]))
			j += 3
			if j+nameLen > len(ext) {
				return "", ErrNotClientHello
			}
			if nameType == 0 { // host_name
				return string(ext[j : j+nameLen]), nil
			}
			j += nameLen
		}
		return "", ErrNotClientHello
	}
	// A ClientHello with no SNI is legal; report empty rather than error.
	return "", nil
}
