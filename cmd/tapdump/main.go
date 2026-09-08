// Command tapdump is a reference reader for GoTapline capture files.
//
// It exists to prove the format round-trips and to give a starting point for a
// purpose-built reader. It renders the timeline; it does not decode payload
// semantics (AES bodies, MessagePack, Diarkis frames) — that is deliberately
// out of scope for the capture layer.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"gotapline/internal/tapfile"
)

func main() {
	var (
		maxBytes  = flag.Int("bytes", 96, "payload bytes to render per record (0 for none, -1 for all)")
		mode      = flag.String("mode", "auto", "payload rendering: auto, hex, text, none")
		onlyUDP   = flag.Bool("udp", false, "only UDP flows")
		onlyTCP   = flag.Bool("tcp", false, "only TCP flows")
		flowID    = flag.Int("flow", 0, "only this flow id")
		statsOnly = flag.Bool("stats", false, "print a summary instead of the timeline")
		relTime   = flag.Bool("rel", false, "show time relative to capture start instead of wall clock")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tapdump [flags] <capture.tap>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	r, err := tapfile.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "tapdump: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()

	h := r.Header()
	start := time.Unix(0, h.WallNs)
	fmt.Printf("# GoTapline capture v%d  pid=%d  started %s\n",
		h.Version, h.PID, start.Format("2006-01-02 15:04:05.000"))

	flows := map[uint32]*flowInfo{}
	var total int

	for {
		rec, err := r.Next()
		if err != nil {
			break
		}
		total++

		if rec.Type == tapfile.TypeFlowOpen {
			fo, ferr := tapfile.UnmarshalFlowOpen(rec.Payload)
			if ferr != nil {
				fmt.Printf("! seq=%d malformed FLOW_OPEN\n", rec.Seq)
				continue
			}
			flows[rec.FlowID] = &flowInfo{FlowOpen: fo}
		}

		fi := flows[rec.FlowID]
		if fi != nil && rec.Type == tapfile.TypeData {
			fi.records++
			if rec.Dir == tapfile.DirC2S {
				fi.bytesC2S += len(rec.Payload)
			} else {
				fi.bytesS2C += len(rec.Payload)
			}
		}

		if *statsOnly {
			continue
		}
		if !wanted(rec, fi, *onlyUDP, *onlyTCP, uint32(*flowID)) {
			continue
		}

		ts := r.WallTime(rec).Format("15:04:05.000000")
		if *relTime {
			ts = fmt.Sprintf("%14.6f", time.Duration(rec.TRelNs).Seconds())
		}

		switch rec.Type {
		case tapfile.TypeMeta:
			fmt.Printf("%s  %6d  META   %s\n", ts, rec.Seq, string(rec.Payload))
		case tapfile.TypeFlowOpen:
			fo := flows[rec.FlowID].FlowOpen
			sni := fo.SNI
			if sni != "" {
				sni = "  sni=" + sni
			}
			fmt.Printf("%s  %6d  OPEN   flow=%d %s/%s  %s -> %s%s\n",
				ts, rec.Seq, rec.FlowID, tapfile.ProtoName(fo.Proto), tapfile.ModeName(fo.Mode),
				fo.Client, fo.Remote, sni)
		case tapfile.TypeFlowClose:
			fmt.Printf("%s  %6d  CLOSE  flow=%d\n", ts, rec.Seq, rec.FlowID)
		case tapfile.TypeData:
			label := "?"
			if fi != nil {
				label = tapfile.ProtoName(fi.Proto)
			}
			fmt.Printf("%s  %6d  DATA   flow=%d %s %s %d bytes\n",
				ts, rec.Seq, rec.FlowID, label, tapfile.DirName(rec.Dir), len(rec.Payload))
			renderPayload(rec.Payload, *mode, *maxBytes)
		}
	}

	if r.Truncated() {
		fmt.Printf("\n# NOTE: file ends in a partial or corrupt record (capture was cut short).\n")
		fmt.Printf("#       Everything printed above is intact.\n")
	}

	ids := make([]uint32, 0, len(flows))
	for id := range flows {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	fmt.Printf("\n# %d records, %d flows\n", total, len(flows))
	for _, id := range ids {
		f := flows[id]
		sni := f.SNI
		if sni == "" {
			sni = "-"
		}
		fmt.Printf("#  flow %-4d %-3s/%-13s %-22s -> %-22s  %4d pkt  c2s=%-8d s2c=%-8d %s\n",
			id, tapfile.ProtoName(f.Proto), tapfile.ModeName(f.Mode),
			f.Client, f.Remote, f.records, f.bytesC2S, f.bytesS2C, sni)
	}
}

// flowInfo accumulates what we know about one flow as the file is walked.
type flowInfo struct {
	tapfile.FlowOpen
	records            int
	bytesC2S, bytesS2C int
}

func wanted(rec tapfile.Record, fi *flowInfo, udpOnly, tcpOnly bool, flow uint32) bool {
	if flow != 0 && rec.FlowID != flow {
		return false
	}
	if !udpOnly && !tcpOnly {
		return true
	}
	if rec.Type == tapfile.TypeMeta {
		return true
	}
	if fi == nil {
		return false
	}
	if udpOnly && fi.Proto != tapfile.ProtoUDP {
		return false
	}
	if tcpOnly && fi.Proto != tapfile.ProtoTCP {
		return false
	}
	return true
}

// renderPayload prints bytes as hex, as text, or as whichever suits.
func renderPayload(p []byte, mode string, max int) {
	if mode == "none" || max == 0 || len(p) == 0 {
		return
	}
	show := p
	truncated := false
	if max > 0 && len(show) > max {
		show, truncated = show[:max], true
	}

	if mode == "auto" {
		if mostlyPrintable(show) {
			mode = "text"
		} else {
			mode = "hex"
		}
	}

	switch mode {
	case "text":
		s := strings.ReplaceAll(string(show), "\r\n", "\n")
		for _, line := range strings.Split(s, "\n") {
			fmt.Printf("           | %s\n", line)
		}
	default:
		for _, line := range strings.Split(strings.TrimRight(hex.Dump(show), "\n"), "\n") {
			fmt.Printf("           | %s\n", line)
		}
	}
	if truncated {
		fmt.Printf("           | ... %d more bytes\n", len(p)-len(show))
	}
}

func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	var ok int
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			ok++
		} else if c >= 0x80 && unicode.IsPrint(rune(c)) {
			ok++
		}
	}
	return ok*10 >= len(b)*8
}
