package tapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"time"
)

// Reader walks the records of a capture file in timeline order.
//
// Next reports io.EOF both for a cleanly exhausted file and for one whose tail
// is a partial record, which is the expected shape of a capture whose process
// was killed. Use Truncated to tell the two apart.
type Reader struct {
	br        *bufio.Reader
	c         io.Closer
	hdr       Header
	truncated bool
}

// NewReader reads the header from r and returns a Reader positioned at the
// first record.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	raw := make([]byte, HeaderLen)
	if _, err := io.ReadFull(br, raw); err != nil {
		return nil, ErrShortHeader
	}
	h, hdrLen, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	// Skip any header extension a future version added.
	if hdrLen > HeaderLen {
		if _, err := br.Discard(hdrLen - HeaderLen); err != nil {
			return nil, ErrShortHeader
		}
	}
	return &Reader{br: br, hdr: h}, nil
}

// Open opens a capture file on disk.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	r.c = f
	return r, nil
}

// Close releases the underlying file, if this Reader owns one.
func (r *Reader) Close() error {
	if r.c != nil {
		return r.c.Close()
	}
	return nil
}

// Header returns the file header.
func (r *Reader) Header() Header { return r.hdr }

// Truncated reports whether iteration stopped on a partial or corrupt record
// rather than a clean end of file.
func (r *Reader) Truncated() bool { return r.truncated }

// WallTime converts a record's monotonic offset to absolute time.
func (r *Reader) WallTime(rec Record) time.Time {
	return time.Unix(0, r.hdr.WallNs).Add(time.Duration(rec.TRelNs))
}

// Next returns the next record, or io.EOF when there are no more.
func (r *Reader) Next() (Record, error) {
	var rec Record

	var lenBuf [4]byte
	if _, err := io.ReadFull(r.br, lenBuf[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			r.truncated = true
		}
		return rec, io.EOF
	}
	recLen := int(binary.LittleEndian.Uint32(lenBuf[:]))

	// A record is at minimum the fixed fields after recLen plus the checksum.
	minLen := recFixedLen - 4 + crcLen
	if recLen < minLen || recLen > MaxPayload+minLen {
		r.truncated = true
		return rec, io.EOF
	}

	body := make([]byte, recLen)
	if _, err := io.ReadFull(r.br, body); err != nil {
		r.truncated = true
		return rec, io.EOF
	}

	// Verify the checksum over recLen ++ body[:len-4].
	want := binary.LittleEndian.Uint32(body[recLen-crcLen:])
	h := crc32.New(crcTable)
	h.Write(lenBuf[:])
	h.Write(body[:recLen-crcLen])
	if h.Sum32() != want {
		r.truncated = true
		return rec, io.EOF
	}

	rec.Seq = binary.LittleEndian.Uint64(body[0:8])
	rec.TRelNs = int64(binary.LittleEndian.Uint64(body[8:16]))
	rec.Type = body[16]
	rec.Dir = body[17]
	rec.Flags = binary.LittleEndian.Uint16(body[18:20])
	rec.FlowID = binary.LittleEndian.Uint32(body[20:24])
	payLen := int(binary.LittleEndian.Uint32(body[24:28]))
	if payLen != recLen-minLen {
		r.truncated = true
		return rec, io.EOF
	}
	if payLen > 0 {
		rec.Payload = body[28 : 28+payLen]
	}
	return rec, nil
}
