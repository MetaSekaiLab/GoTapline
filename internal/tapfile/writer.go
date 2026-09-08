package tapfile

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Writer appends records to a capture file.
//
// All appends funnel through one mutex, and the sequence number and timestamp
// are taken inside it. That is what makes the file a single authoritative
// timeline: concurrent UDP relays and TLS bridges cannot interleave in a way
// that leaves the recorded order disagreeing with the order things happened.
//
// A Writer is safe for concurrent use.
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	bw     *bufio.Writer
	seq    uint64
	t0     time.Time
	closed bool

	nextFlowID atomic.Uint32
	dropped    atomic.Uint64
}

// Create opens path for writing and emits the file header.
func Create(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	h := Header{
		Version: Version,
		WallNs:  now.UnixNano(),
		MonoNs:  0, // records are offsets from t0, so the base is 0 by definition
		PID:     uint32(os.Getpid()),
	}
	w := &Writer{f: f, bw: bufio.NewWriterSize(f, 1<<20), t0: now}
	if _, err := w.bw.Write(h.marshal()); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

// NextFlowID hands out a unique flow identifier.
func (w *Writer) NextFlowID() uint32 { return w.nextFlowID.Add(1) }

// append writes one record. It is the single choke point for ordering.
func (w *Writer) append(typ, dir uint8, flags uint16, flowID uint32, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	w.seq++
	rec := Record{
		Seq: w.seq,
		// time.Since uses the monotonic reading carried in t0, so this is
		// immune to wall-clock changes.
		TRelNs:  int64(time.Since(w.t0)),
		Type:    typ,
		Dir:     dir,
		Flags:   flags,
		FlowID:  flowID,
		Payload: payload,
	}
	_, err := w.bw.Write(marshalRecord(rec))
	return err
}

// FlowOpen records the start of a flow and returns its identifier.
func (w *Writer) FlowOpen(f FlowOpen) (uint32, error) {
	id := w.NextFlowID()
	return id, w.append(TypeFlowOpen, DirNone, 0, id, MarshalFlowOpen(f))
}

// Data records captured bytes for a flow.
//
// payload is copied into the record immediately, so callers may reuse their
// buffer as soon as Data returns.
func (w *Writer) Data(flowID uint32, dir uint8, payload []byte) error {
	if len(payload) > MaxPayload {
		payload = payload[:MaxPayload]
	}
	return w.append(TypeData, dir, 0, flowID, payload)
}

// FlowClose records the end of a flow.
func (w *Writer) FlowClose(flowID uint32) error {
	return w.append(TypeFlowClose, DirNone, 0, flowID, nil)
}

// Meta records a free-form UTF-8 note, useful for marking the start of a run
// or annotating a moment while capturing.
func (w *Writer) Meta(format string, args ...any) error {
	return w.append(TypeMeta, DirNone, 0, 0, []byte(fmt.Sprintf(format, args...)))
}

// NoteDrop counts a datagram that could not be recorded, so the run can report
// whether it lost anything.
func (w *Writer) NoteDrop() { w.dropped.Add(1) }

// Stats reports progress for the run.
func (w *Writer) Stats() (records uint64, dropped uint64) {
	w.mu.Lock()
	n := w.seq
	w.mu.Unlock()
	return n, w.dropped.Load()
}

// Flush pushes buffered records to the OS without closing.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bw.Flush()
}

// Close flushes, fsyncs and closes the file. Calling it twice is harmless.
//
// The fsync matters: it is what guarantees that a capture ends at a record
// boundary rather than mid-record when the process exits.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}
