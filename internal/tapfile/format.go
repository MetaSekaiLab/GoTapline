// Package tapfile implements the GoTapline private capture format.
//
// A capture file is a 48-byte header followed by an unbounded sequence of
// length-prefixed, CRC-protected records. It is append-only and streamable:
// a reader can follow a file that is still being written, and a file truncated
// by a crash stays readable up to its last intact record.
//
// The format's whole reason for existing is the unified timeline. Every record
// carries a strictly increasing sequence number and a monotonic-clock offset,
// both taken under one mutex at append time, so UDP datagrams and decrypted
// TLS plaintext land in one true total order rather than two streams merged after
// the fact.
//
// See FORMAT.md for the normative on-disk specification.
package tapfile

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Magic identifies a GoTapline capture file.
var Magic = [8]byte{'G', 'O', 'T', 'A', 'P', 'L', 'N', 0x00}

const (
	// Version is the format version this package reads and writes.
	Version uint16 = 1

	// HeaderLen is the fixed size of the file header.
	HeaderLen = 48

	// recFixedLen is the per-record byte count before the payload:
	// recLen(4) seq(8) tRelNs(8) type(1) dir(1) flags(2) flowID(4) payLen(4).
	recFixedLen = 32

	// crcLen is the trailing checksum size.
	crcLen = 4

	// MaxPayload caps a single record payload, bounding reader allocation on a
	// corrupt length field. 64 MiB is far above any real datagram or TLS chunk.
	MaxPayload = 64 << 20
)

// Record types.
const (
	TypeFlowOpen  uint8 = 1 // a flow began; payload describes it
	TypeData      uint8 = 2 // payload is captured bytes
	TypeFlowClose uint8 = 3 // a flow ended
	TypeMeta      uint8 = 4 // payload is a UTF-8 note
)

// Directions.
const (
	DirC2S  uint8 = 0 // client -> server
	DirS2C  uint8 = 1 // server -> client
	DirNone uint8 = 2 // not directional (meta, flow close)
)

// Flow protocols, carried in a FlowOpen payload.
const (
	ProtoTCP uint8 = 1
	ProtoUDP uint8 = 2
)

// Flow capture modes, carried in a FlowOpen payload.
const (
	ModeRaw          uint8 = 1 // bytes as they appeared on the wire
	ModeTLSPlaintext uint8 = 2 // TLS was terminated; DATA is decrypted plaintext
	ModeTLSOpaque    uint8 = 3 // TLS was tunnelled untouched; DATA (if any) is ciphertext
)

// crcTable is the Castagnoli polynomial, which has hardware support on arm64
// and x86-64 and so costs essentially nothing per record.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Header is the once-per-file preamble.
//
// WallNs and MonoNs are both sampled at t0. Records store only a monotonic
// offset from MonoNs, so a wall-clock adjustment mid-capture cannot reorder or
// dilate the timeline; a reader recovers absolute time as WallNs + TRelNs.
type Header struct {
	Version uint16
	Flags   uint32
	WallNs  int64
	MonoNs  int64
	PID     uint32
}

// Record is one entry in the timeline.
type Record struct {
	Seq     uint64
	TRelNs  int64
	Type    uint8
	Dir     uint8
	Flags   uint16
	FlowID  uint32
	Payload []byte
}

// FlowOpen is the decoded payload of a TypeFlowOpen record. It is
// self-describing so a reader needs no out-of-band configuration.
type FlowOpen struct {
	Proto  uint8
	Mode   uint8
	Client string
	Remote string
	SNI    string
}

// Errors reported by this package.
var (
	ErrBadMagic     = errors.New("tapfile: bad magic")
	ErrBadVersion   = errors.New("tapfile: unsupported version")
	ErrShortHeader  = errors.New("tapfile: truncated header")
	ErrPayloadRange = errors.New("tapfile: payload length out of range")
	ErrChecksum     = errors.New("tapfile: checksum mismatch")
	ErrMalformed    = errors.New("tapfile: malformed record")
)

func (h Header) marshal() []byte {
	b := make([]byte, HeaderLen)
	copy(b[0:8], Magic[:])
	binary.LittleEndian.PutUint16(b[8:10], h.Version)
	binary.LittleEndian.PutUint16(b[10:12], uint16(HeaderLen))
	binary.LittleEndian.PutUint32(b[12:16], h.Flags)
	binary.LittleEndian.PutUint64(b[16:24], uint64(h.WallNs))
	binary.LittleEndian.PutUint64(b[24:32], uint64(h.MonoNs))
	binary.LittleEndian.PutUint32(b[32:36], h.PID)
	// b[36:48] reserved, left zero
	return b
}

func parseHeader(b []byte) (Header, int, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, 0, ErrShortHeader
	}
	if string(b[0:8]) != string(Magic[:]) {
		return h, 0, ErrBadMagic
	}
	h.Version = binary.LittleEndian.Uint16(b[8:10])
	if h.Version != Version {
		return h, 0, ErrBadVersion
	}
	hdrLen := int(binary.LittleEndian.Uint16(b[10:12]))
	if hdrLen < HeaderLen {
		return h, 0, ErrShortHeader
	}
	h.Flags = binary.LittleEndian.Uint32(b[12:16])
	h.WallNs = int64(binary.LittleEndian.Uint64(b[16:24]))
	h.MonoNs = int64(binary.LittleEndian.Uint64(b[24:32]))
	h.PID = binary.LittleEndian.Uint32(b[32:36])
	return h, hdrLen, nil
}

// marshalRecord serialises a record, including its trailing checksum.
func marshalRecord(r Record) []byte {
	n := recFixedLen + len(r.Payload) + crcLen
	b := make([]byte, n)
	// recLen counts everything after the recLen field itself.
	binary.LittleEndian.PutUint32(b[0:4], uint32(n-4))
	binary.LittleEndian.PutUint64(b[4:12], r.Seq)
	binary.LittleEndian.PutUint64(b[12:20], uint64(r.TRelNs))
	b[20] = r.Type
	b[21] = r.Dir
	binary.LittleEndian.PutUint16(b[22:24], r.Flags)
	binary.LittleEndian.PutUint32(b[24:28], r.FlowID)
	binary.LittleEndian.PutUint32(b[28:32], uint32(len(r.Payload)))
	copy(b[recFixedLen:], r.Payload)
	binary.LittleEndian.PutUint32(b[n-crcLen:], crc32.Checksum(b[:n-crcLen], crcTable))
	return b
}

// MarshalFlowOpen encodes a flow description.
func MarshalFlowOpen(f FlowOpen) []byte {
	b := make([]byte, 0, 8+len(f.Client)+len(f.Remote)+len(f.SNI))
	b = append(b, f.Proto, f.Mode)
	b = append(b, byte(len(f.Client)))
	b = append(b, f.Client...)
	b = append(b, byte(len(f.Remote)))
	b = append(b, f.Remote...)
	var sniLen [2]byte
	binary.LittleEndian.PutUint16(sniLen[:], uint16(len(f.SNI)))
	b = append(b, sniLen[:]...)
	b = append(b, f.SNI...)
	return b
}

// UnmarshalFlowOpen decodes a flow description.
func UnmarshalFlowOpen(b []byte) (FlowOpen, error) {
	var f FlowOpen
	if len(b) < 3 {
		return f, ErrMalformed
	}
	f.Proto, f.Mode = b[0], b[1]
	i := 2

	take8 := func() (string, bool) {
		if i >= len(b) {
			return "", false
		}
		n := int(b[i])
		i++
		if i+n > len(b) {
			return "", false
		}
		s := string(b[i : i+n])
		i += n
		return s, true
	}

	var ok bool
	if f.Client, ok = take8(); !ok {
		return f, ErrMalformed
	}
	if f.Remote, ok = take8(); !ok {
		return f, ErrMalformed
	}
	if i+2 > len(b) {
		return f, ErrMalformed
	}
	n := int(binary.LittleEndian.Uint16(b[i : i+2]))
	i += 2
	if i+n > len(b) {
		return f, ErrMalformed
	}
	f.SNI = string(b[i : i+n])
	return f, nil
}

// ProtoName renders a protocol constant for display.
func ProtoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return "proto?"
}

// ModeName renders a capture-mode constant for display.
func ModeName(m uint8) string {
	switch m {
	case ModeRaw:
		return "raw"
	case ModeTLSPlaintext:
		return "tls-plaintext"
	case ModeTLSOpaque:
		return "tls-opaque"
	}
	return "mode?"
}

// TypeName renders a record type for display.
func TypeName(t uint8) string {
	switch t {
	case TypeFlowOpen:
		return "OPEN"
	case TypeData:
		return "DATA"
	case TypeFlowClose:
		return "CLOSE"
	case TypeMeta:
		return "META"
	}
	return "TYPE?"
}

// DirName renders a direction for display.
func DirName(d uint8) string {
	switch d {
	case DirC2S:
		return "C->S"
	case DirS2C:
		return "S->C"
	case DirNone:
		return "  - "
	}
	return "DIR?"
}
