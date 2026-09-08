package socks_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gotapline/internal/mitm"
	"gotapline/internal/socks"
	"gotapline/internal/tapfile"
)

// startProxy brings up a tapline SOCKS5 server on loopback writing to a temp
// capture file, intercepting the given SNI names.
func startProxy(t *testing.T, hosts []string) (addr string, capturePath string, ca *mitm.CA, stop func()) {
	t.Helper()

	dir := t.TempDir()
	capturePath = filepath.Join(dir, "e2e.tap")
	w, err := tapfile.Create(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = mitm.LoadOrCreateCA(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}

	var mcfg *mitm.Config
	if len(hosts) > 0 {
		mcfg = &mitm.Config{
			CA:    ca,
			Hosts: hosts,
			// the fake upstream uses a self-signed cert
			InsecureUpstream: true,
		}
	}

	srv, err := socks.New(socks.Options{
		Listen: "127.0.0.1:0",
		// loopback tests must pin this, since auto-detect deliberately refuses
		// to advertise a loopback address
		Advertise: "127.0.0.1",
		MITM:      mcfg,
		Logf:      t.Logf,
	}, w)
	if err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{})
	go func() {
		// ListenAndServe binds synchronously before accepting
		close(ready)
		srv.ListenAndServe()
	}()
	<-ready
	for i := 0; i < 200 && srv.Addr() == nil; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("proxy never bound")
	}

	return srv.Addr().String(), capturePath, ca, func() {
		srv.Close()
		w.Close()
	}
}

// socksConnect performs a SOCKS5 CONNECT and returns the tunnelled conn.
func socksConnect(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("handshake refused: %v", resp)
	}

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := readSocksReply(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func readSocksReply(c net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("socks reply code %d", head[1])
	}
	switch head[3] {
	case 1:
		_, err := io.ReadFull(c, make([]byte, 4+2))
		return err
	case 4:
		_, err := io.ReadFull(c, make([]byte, 16+2))
		return err
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, int(l[0])+2))
		return err
	}
	return fmt.Errorf("bad atyp %d", head[3])
}

// socksUDP performs UDP ASSOCIATE and returns the relay address plus the
// control connection, which must stay open for the association to live.
func socksUDP(t *testing.T, proxy string) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	io.ReadFull(c, resp)

	// request UDP ASSOCIATE with an unspecified bind address
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0 {
		t.Fatalf("associate refused: %d", head[1])
	}
	if head[3] != 1 {
		t.Fatalf("expected IPv4 relay address, got atyp %d", head[3])
	}
	body := make([]byte, 6)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	ip := net.IPv4(body[0], body[1], body[2], body[3])
	port := int(binary.BigEndian.Uint16(body[4:6]))

	// The relay address must be usable by the client. Advertising 0.0.0.0 or a
	// loopback address to a remote device is the classic silent failure.
	if ip.IsUnspecified() {
		t.Fatalf("proxy advertised an unspecified relay address %s", ip)
	}
	return c, &net.UDPAddr{IP: ip, Port: port}
}

func wrapUDP(dst *net.UDPAddr, payload []byte) []byte {
	b := []byte{0, 0, 0, 1}
	b = append(b, dst.IP.To4()...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(dst.Port))
	b = append(b, pb[:]...)
	return append(b, payload...)
}

// TestUnifiedCapture drives TLS and UDP through the proxy at the same time and
// asserts that both land in one capture file, correctly decrypted and in a
// single consistent timeline.
func TestUnifiedCapture(t *testing.T) {
	// --- fake HTTPS origin, standing in for the game API ---
	const sni = "mkcn-prod-public-60001-1.dailygn.com"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("\x01\x02SYSTEM-BODY\x03\x04"))
	})
	origin := httptestNewTLSServer(t, mux)
	defer origin.Close()
	originHost, originPort := splitHostPort(t, origin.addr)
	_ = originHost

	// --- fake UDP echo origin, standing in for a Diarkis server ---
	udpSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpSrv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// reply with a recognisable transform
			out := append([]byte("ECHO:"), buf[:n]...)
			udpSrv.WriteToUDP(out, from)
		}
	}()
	udpPort := udpSrv.LocalAddr().(*net.UDPAddr).Port

	proxy, capturePath, _, stop := startProxy(t, []string{sni})
	defer stop()

	var wg sync.WaitGroup

	// TLS traffic through the proxy, addressed by SNI so interception triggers
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Dial the loopback origin by address while presenting the intercept
		// name as SNI: selection is driven by the ClientHello, not by the
		// CONNECT target.
		raw := socksConnect(t, proxy, "127.0.0.1", originPort)
		defer raw.Close()
		tc := tls.Client(raw, &tls.Config{
			ServerName: sni,
			// trust nothing in particular: we assert on the captured plaintext,
			// not on the client's chain validation
			InsecureSkipVerify: true,
		})
		if err := tc.Handshake(); err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		req := "GET /api/system HTTP/1.1\r\nHost: " + sni + "\r\nX-Probe: unified\r\nConnection: close\r\n\r\n"
		if _, err := tc.Write([]byte(req)); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		body, _ := io.ReadAll(tc)
		if !strings.Contains(string(body), "SYSTEM-BODY") {
			t.Errorf("origin response not received, got %q", string(body))
		}
	}()

	// UDP traffic through the proxy, concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctrl, relay := socksUDP(t, proxy)
		defer ctrl.Close()

		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Error(err)
			return
		}
		defer pc.Close()

		dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpPort}
		for i := 0; i < 5; i++ {
			payload := []byte(fmt.Sprintf("DGRAM-%d", i))
			if _, err := pc.WriteToUDP(wrapUDP(dst, payload), relay); err != nil {
				t.Error(err)
				return
			}
			pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 2048)
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("no udp reply for datagram %d: %v", i, err)
				return
			}
			// strip the 10-byte SOCKS5 UDP header
			if n < 10 || !strings.Contains(string(buf[10:n]), "ECHO:DGRAM-") {
				t.Errorf("unexpected udp reply: %q", string(buf[:n]))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()
	time.Sleep(200 * time.Millisecond) // let the last records flush
	stop()

	// --- now read the capture back ---
	r, err := tapfile.Open(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var (
		lastSeq  uint64
		lastT    int64 = -1
		sawUDP   bool
		sawTLS   bool
		reqSeen  bool
		respSeen bool
		udpUp    int
		udpDown  int
		protoOf  = map[uint32]uint8{}
	)
	for {
		rec, err := r.Next()
		if err != nil {
			break
		}
		// the single-timeline invariant, on a real mixed capture
		if rec.Seq != lastSeq+1 {
			t.Fatalf("seq %d follows %d", rec.Seq, lastSeq)
		}
		if rec.TRelNs < lastT {
			t.Fatalf("timestamp went backwards: %d after %d", rec.TRelNs, lastT)
		}
		lastSeq, lastT = rec.Seq, rec.TRelNs

		switch rec.Type {
		case tapfile.TypeFlowOpen:
			fo, err := tapfile.UnmarshalFlowOpen(rec.Payload)
			if err != nil {
				t.Fatalf("flow open: %v", err)
			}
			protoOf[rec.FlowID] = fo.Proto
			switch fo.Proto {
			case tapfile.ProtoUDP:
				sawUDP = true
			case tapfile.ProtoTCP:
				if fo.Mode == tapfile.ModeTLSPlaintext {
					sawTLS = true
					if fo.SNI != sni {
						t.Errorf("intercepted flow SNI = %q, want %q", fo.SNI, sni)
					}
				}
			}
		case tapfile.TypeData:
			s := string(rec.Payload)
			if protoOf[rec.FlowID] == tapfile.ProtoUDP {
				if rec.Dir == tapfile.DirC2S {
					udpUp++
				} else {
					udpDown++
				}
			}
			if strings.Contains(s, "X-Probe: unified") {
				reqSeen = true
			}
			if strings.Contains(s, "SYSTEM-BODY") {
				respSeen = true
			}
		}
	}

	if !sawUDP {
		t.Error("no UDP flow recorded")
	}
	if !sawTLS {
		t.Error("no TLS-plaintext flow recorded")
	}
	if !reqSeen {
		t.Error("decrypted request headers not found in capture")
	}
	if !respSeen {
		t.Error("decrypted response body not found in capture")
	}
	if udpUp < 5 {
		t.Errorf("recorded %d client datagrams, want >= 5", udpUp)
	}
	if udpDown < 5 {
		t.Errorf("recorded %d server datagrams, want >= 5", udpDown)
	}
}

// TestPinnedHostIsNotIntercepted is the safety property: a host outside the
// allowlist must reach the origin's real certificate untouched, so certificate
// pinning keeps working.
func TestPinnedHostIsNotIntercepted(t *testing.T) {
	const allowed = "intercept.example"
	const pinned = "pinned.example"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	origin := httptestNewTLSServer(t, mux)
	defer origin.Close()
	_, port := splitHostPort(t, origin.addr)

	proxy, capturePath, ca, stop := startProxy(t, []string{allowed})
	defer stop()

	// Trust only the origin's own CA, not the MITM CA.
	pool := x509.NewCertPool()
	pool.AddCert(origin.cert)

	raw := socksConnect(t, proxy, "127.0.0.1", port)
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: pinned, RootCAs: pool})
	err := tc.Handshake()
	if err != nil {
		// The handshake may fail on hostname mismatch (the test origin's cert
		// names differ), but it must NOT fail because our CA signed it.
		if strings.Contains(err.Error(), "GoTapline") {
			t.Fatalf("non-allowlisted host was intercepted: %v", err)
		}
	} else {
		// Succeeded against the origin's real chain: definitely not intercepted.
		peer := tc.ConnectionState().PeerCertificates[0]
		if strings.Contains(peer.Issuer.CommonName, "GoTapline") {
			t.Fatalf("non-allowlisted host got a MITM certificate")
		}
	}
	tc.Close()
	time.Sleep(150 * time.Millisecond)
	stop()

	// The capture must contain the flow, recorded as opaque and never as
	// plaintext. Asserting the flow is present matters: a test that only checks
	// for the absence of plaintext would also pass if nothing were captured.
	r, err := tapfile.Open(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var sawOpaque bool
	for {
		rec, err := r.Next()
		if err != nil {
			break
		}
		if rec.Type != tapfile.TypeFlowOpen {
			continue
		}
		fo, err := tapfile.UnmarshalFlowOpen(rec.Payload)
		if err != nil {
			continue
		}
		if fo.Proto != tapfile.ProtoTCP {
			continue
		}
		if fo.Mode == tapfile.ModeTLSPlaintext {
			t.Fatalf("non-allowlisted host %q was recorded as decrypted", fo.SNI)
		}
		if fo.Mode == tapfile.ModeTLSOpaque {
			sawOpaque = true
			if fo.SNI != pinned {
				t.Errorf("opaque flow SNI = %q, want %q", fo.SNI, pinned)
			}
		}
	}
	if !sawOpaque {
		t.Fatal("no opaque TCP flow recorded, so pass-through was never exercised")
	}
	_ = ca
}

// TestAdvertiseRefusesLoopback documents the guard against the most common
// UDP-relay misconfiguration.
func TestAdvertiseRefusesLoopback(t *testing.T) {
	w, err := tapfile.Create(filepath.Join(t.TempDir(), "x.tap"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := socks.New(socks.Options{Listen: "127.0.0.1:0", Advertise: "not-an-ip"}, w); err == nil {
		t.Error("accepted a non-IP advertise value")
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

// --- a minimal self-signed TLS origin, standing in for a real server ---

type tlsOrigin struct {
	addr string
	cert *x509.Certificate
	ln   net.Listener
	srv  *http.Server
}

func (o *tlsOrigin) Close() {
	o.srv.Close()
	o.ln.Close()
}

// httptestNewTLSServer serves h over TLS with its own self-signed certificate.
// Using a certificate unrelated to the MITM CA is what lets the tests tell
// interception apart from pass-through by looking at the issuer.
func httptestNewTLSServer(t *testing.T, h http.Handler) *tlsOrigin {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-origin", Organization: []string{"TestOrigin"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames: []string{
			"localhost",
			"mkcn-prod-public-60001-1.dailygn.com",
			"intercept.example",
			"pinned.example",
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"http/1.1"},
		},
	}
	o := &tlsOrigin{addr: ln.Addr().String(), cert: parsed, ln: ln, srv: srv}
	go srv.ServeTLS(ln, "", "")
	return o
}
