package tapfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func tmpFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "c.tap")
}

func TestRoundTrip(t *testing.T) {
	path := tmpFile(t)
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Meta("run start ver=%d", Version); err != nil {
		t.Fatal(err)
	}
	fid, err := w.FlowOpen(FlowOpen{
		Proto: ProtoUDP, Mode: ModeRaw,
		Client: "192.168.50.35:52199", Remote: "14.103.235.2:7200",
	})
	if err != nil {
		t.Fatal(err)
	}
	up := []byte{0xFE, 0xBE, 0xDE, 0xEF, 0x00}
	down := []byte{0x00, 0x00, 0x00, 0x04}
	if err := w.Data(fid, DirC2S, up); err != nil {
		t.Fatal(err)
	}
	if err := w.Data(fid, DirS2C, down); err != nil {
		t.Fatal(err)
	}
	// an empty payload must survive too
	if err := w.Data(fid, DirC2S, nil); err != nil {
		t.Fatal(err)
	}
	tid, err := w.FlowOpen(FlowOpen{
		Proto: ProtoTCP, Mode: ModeTLSPlaintext,
		Client: "192.168.50.35:5001", Remote: "1.2.3.4:443",
		SNI: "mkcn-prod-public-60001-1.dailygn.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Data(tid, DirC2S, []byte("GET /api/system HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.FlowClose(fid); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var recs []Record
	for {
		rec, err := r.Next()
		if err != nil {
			break
		}
		recs = append(recs, rec)
	}
	if r.Truncated() {
		t.Fatal("clean file reported as truncated")
	}
	if len(recs) != 8 {
		t.Fatalf("got %d records, want 8", len(recs))
	}

	// sequence numbers are 1-based and gapless
	for i, rec := range recs {
		if rec.Seq != uint64(i+1) {
			t.Errorf("record %d: seq %d, want %d", i, rec.Seq, i+1)
		}
	}

	// payload fidelity
	if !bytes.Equal(recs[2].Payload, up) {
		t.Errorf("c2s payload: got %x want %x", recs[2].Payload, up)
	}
	if !bytes.Equal(recs[3].Payload, down) {
		t.Errorf("s2c payload: got %x want %x", recs[3].Payload, down)
	}
	if len(recs[4].Payload) != 0 {
		t.Errorf("empty payload came back as %x", recs[4].Payload)
	}

	// flow descriptions survive, including the SNI
	fo, err := UnmarshalFlowOpen(recs[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if fo.Proto != ProtoUDP || fo.Remote != "14.103.235.2:7200" || fo.SNI != "" {
		t.Errorf("udp flow decoded as %+v", fo)
	}
	to, err := UnmarshalFlowOpen(recs[5].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if to.Mode != ModeTLSPlaintext || to.SNI != "mkcn-prod-public-60001-1.dailygn.com" {
		t.Errorf("tcp flow decoded as %+v", to)
	}

	// absolute time reconstruction is anchored to the header
	if got := r.WallTime(recs[0]).UnixNano(); got < r.Header().WallNs {
		t.Errorf("WallTime %d predates header %d", got, r.Header().WallNs)
	}
}

// TestUnifiedTimeline is the property the format exists for: many concurrent
// producers, one authoritative order. Sequence numbers must be gapless and
// timestamps must be non-decreasing in file order.
func TestUnifiedTimeline(t *testing.T) {
	path := tmpFile(t)
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}

	const writers, each = 16, 200
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			fid := w.NextFlowID()
			for j := 0; j < each; j++ {
				dir := DirC2S
				if j%2 == 1 {
					dir = DirS2C
				}
				if err := w.Data(fid, dir, []byte{byte(n), byte(j)}); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var n int
	var lastSeq uint64
	var lastT int64 = -1
	for {
		rec, err := r.Next()
		if err != nil {
			break
		}
		n++
		if rec.Seq != lastSeq+1 {
			t.Fatalf("record %d: seq %d follows %d (gap or reorder)", n, rec.Seq, lastSeq)
		}
		if rec.TRelNs < lastT {
			t.Fatalf("record %d: timestamp %d went backwards from %d", n, rec.TRelNs, lastT)
		}
		lastSeq, lastT = rec.Seq, rec.TRelNs
	}
	if want := writers * each; n != want {
		t.Fatalf("read %d records, want %d", n, want)
	}
	if r.Truncated() {
		t.Error("clean file reported as truncated")
	}
}

// TestTruncationTolerated simulates the process being killed mid-record: every
// intact record before the cut must still be readable.
func TestTruncationTolerated(t *testing.T) {
	path := tmpFile(t)
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const total = 50
	fid, _ := w.FlowOpen(FlowOpen{Proto: ProtoUDP, Mode: ModeRaw, Client: "c", Remote: "r"})
	for i := 0; i < total; i++ {
		if err := w.Data(fid, DirC2S, bytes.Repeat([]byte{byte(i)}, 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Cut at a few awkward offsets, including mid-header and mid-record.
	for _, cut := range []int{HeaderLen + 5, HeaderLen + 40, len(full) - 3, len(full) - 1} {
		cutPath := filepath.Join(t.TempDir(), "cut.tap")
		if err := os.WriteFile(cutPath, full[:cut], 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := Open(cutPath)
		if err != nil {
			t.Fatalf("cut=%d: open: %v", cut, err)
		}
		var n int
		for {
			if _, err := r.Next(); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Errorf("cut=%d: unexpected error %v", cut, err)
				}
				break
			}
			n++
		}
		if !r.Truncated() {
			t.Errorf("cut=%d: truncation not reported", cut)
		}
		if n == 0 && cut > HeaderLen+40 {
			t.Errorf("cut=%d: read nothing from a mostly intact file", cut)
		}
		r.Close()
	}
}

// TestCorruptionDetected ensures a flipped byte does not silently yield wrong data.
func TestCorruptionDetected(t *testing.T) {
	path := tmpFile(t)
	w, _ := Create(path)
	fid, _ := w.FlowOpen(FlowOpen{Proto: ProtoUDP, Mode: ModeRaw, Client: "c", Remote: "r"})
	for i := 0; i < 5; i++ {
		w.Data(fid, DirC2S, []byte("payloadpayload"))
	}
	w.Close()

	full, _ := os.ReadFile(path)
	// corrupt a payload byte in the middle of the file
	bad := append([]byte(nil), full...)
	bad[len(bad)/2] ^= 0xFF
	badPath := filepath.Join(t.TempDir(), "bad.tap")
	os.WriteFile(badPath, bad, 0o644)

	r, err := Open(badPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for {
		if _, err := r.Next(); err != nil {
			break
		}
	}
	if !r.Truncated() {
		t.Error("corrupted record was accepted")
	}
}

func TestRejectsForeignFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.tap")
	os.WriteFile(p, bytes.Repeat([]byte("not a tapline file "), 8), 0o644)
	if _, err := Open(p); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("got %v, want ErrBadMagic", err)
	}
}
