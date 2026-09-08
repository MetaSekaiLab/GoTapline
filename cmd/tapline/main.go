// Command tapline is a capturing SOCKS5 proxy.
//
// It records UDP datagrams and decrypted TLS plaintext into one file with a
// single monotonic timeline, so traffic from different transports can be read
// back in the exact order it happened.
//
// The capture layer deliberately stops at "raw bytes, TLS removed": it does not
// interpret payloads. Semantic decoding belongs in a separate reader built
// against FORMAT.md.
//
// Typical use, capturing an iPad through Shadowrocket:
//
//	tapline -listen :1080 -out run.tap -mitm mkcn-prod-public-60001-1.dailygn.com
//
// Point Shadowrocket at this host on port 1080 as a SOCKS5 proxy with UDP
// enabled, turn OFF Shadowrocket's own HTTPS decryption, and install plus trust
// the CA printed at startup.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"gotapline/internal/mitm"
	"gotapline/internal/socks"
	"gotapline/internal/tapfile"
)

// hostList collects SNI names from a flag that may be repeated and may also
// carry comma-separated values, so -mitm a,b and -mitm a -mitm b both work.
//
// Go's default string flag silently keeps only the last occurrence, which would
// mean a capture quietly covering fewer hosts than the operator asked for.
type hostList []string

func (h *hostList) String() string { return strings.Join(*h, ",") }

func (h *hostList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if slices.Contains(*h, part) {
			continue // tolerate duplicates rather than intercepting twice
		}
		*h = append(*h, part)
	}
	return nil
}

func main() {
	var mitmHosts hostList
	flag.Var(&mitmHosts, "mitm",
		"SNI name to decrypt; '*.' prefix matches subdomains. Repeatable, and accepts a comma-separated list. Empty disables MITM")

	var (
		listen    = flag.String("listen", ":1080", "SOCKS5 listen address")
		out       = flag.String("out", "", "capture file (default capture-<timestamp>.tap)")
		caDir     = flag.String("ca-dir", defaultCADir(), "directory holding the MITM CA")
		advertise = flag.String("advertise", "", "IP to advertise for UDP relay (default: auto-detect the outbound interface)")
		allowH2   = flag.Bool("allow-h2", false, "offer HTTP/2 when intercepting; leaving this off keeps the recorded plaintext readable HTTP/1.1")
		recOpaque = flag.Bool("record-opaque", false, "also record ciphertext of connections that were not decrypted")
		insecure  = flag.Bool("insecure-upstream", false, "skip verification of the real server's certificate")
		printCA   = flag.Bool("print-ca", false, "print the CA certificate path and fingerprint, then exit")
		quiet     = flag.Bool("quiet", false, "only log errors")
	)
	flag.Parse()

	ca, err := mitm.LoadOrCreateCA(*caDir)
	if err != nil {
		log.Fatalf("tapline: CA: %v", err)
	}

	if *printCA {
		fmt.Printf("certificate : %s\n", mitm.CertPath(*caDir))
		fmt.Printf("subject     : %s\n", ca.Subject())
		fmt.Printf("sha256      : %s\n", ca.Fingerprint())
		return
	}

	path := *out
	if path == "" {
		path = fmt.Sprintf("capture-%s.tap", time.Now().Format("20060102-150405"))
	}
	w, err := tapfile.Create(path)
	if err != nil {
		log.Fatalf("tapline: create %s: %v", path, err)
	}

	var mcfg *mitm.Config
	hosts := []string(mitmHosts)
	if len(hosts) > 0 {
		mcfg = &mitm.Config{
			CA:               ca,
			Hosts:            hosts,
			AllowH2:          *allowH2,
			InsecureUpstream: *insecure,
		}
	}

	logf := log.Printf
	if *quiet {
		logf = func(string, ...any) {}
	}

	srv, err := socks.New(socks.Options{
		Listen:       *listen,
		Advertise:    *advertise,
		MITM:         mcfg,
		RecordOpaque: *recOpaque,
		Logf:         logf,
	}, w)
	if err != nil {
		w.Close()
		log.Fatalf("tapline: %v", err)
	}

	w.Meta("tapline start listen=%s mitm=%v allow-h2=%v record-opaque=%v advertise=%s ca-sha256=%s",
		*listen, hosts, *allowH2, *recOpaque, srv.AdvertiseIP(), ca.Fingerprint())

	fmt.Printf("capture     : %s\n", path)
	fmt.Printf("socks5      : %s   (UDP relay advertised as %s)\n", *listen, srv.AdvertiseIP())
	if mcfg != nil {
		fmt.Printf("decrypting  : %s\n", strings.Join(hosts, ", "))
		fmt.Printf("             (everything else is tunnelled untouched, so pinned hosts keep working)\n")
		fmt.Printf("CA to trust : %s\n", mitm.CertPath(*caDir))
		fmt.Printf("CA sha256   : %s\n", ca.Fingerprint())
		if !*allowH2 {
			fmt.Printf("ALPN        : http/1.1 only, so recorded plaintext stays readable\n")
		}
	} else {
		fmt.Printf("decrypting  : nothing (-mitm not set); TLS is tunnelled untouched\n")
	}
	fmt.Println()

	// Graceful shutdown: the final Close flushes and fsyncs, which is what
	// guarantees the file ends on a record boundary.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	// Periodically flush so a capture being watched live stays current.
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			w.Flush()
		case sig := <-stop:
			fmt.Printf("\n%v received, closing capture...\n", sig)
			srv.Close()
			w.Meta("tapline stop signal=%v", sig)
			n, dropped := w.Stats()
			if err := w.Close(); err != nil {
				log.Printf("tapline: close: %v", err)
			}
			fmt.Printf("records     : %d\n", n)
			if dropped > 0 {
				fmt.Printf("dropped     : %d  (capture is incomplete)\n", dropped)
			}
			fmt.Printf("file        : %s\n", path)
			return
		case err := <-errc:
			if err != nil {
				log.Printf("tapline: serve: %v", err)
			}
			w.Meta("tapline stop serve-ended")
			w.Close()
			return
		}
	}
}

func defaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tapline"
	}
	return filepath.Join(home, ".tapline")
}
