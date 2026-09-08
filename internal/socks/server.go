// Package socks implements the SOCKS5 subset a capture proxy needs: CONNECT
// for TCP and UDP ASSOCIATE for datagrams, with every byte teed into a
// tapfile.Writer so both transports share one timeline.
package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"gotapline/internal/mitm"
	"gotapline/internal/tapfile"
)

// SOCKS5 wire constants.
const (
	ver5 = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

// Options configures the server.
type Options struct {
	// Listen is the TCP address the proxy accepts SOCKS5 on, e.g. ":1080".
	Listen string

	// Advertise is the address reported to clients in the UDP ASSOCIATE reply.
	// It must be reachable from the device: replying with a loopback address is
	// the classic failure, because the client then sends its datagrams to
	// itself. Empty means auto-detect the outbound interface.
	Advertise string

	// MITM configures selective TLS interception. Nil disables it entirely.
	MITM *mitm.Config

	// RecordOpaque also records the ciphertext of connections that were not
	// intercepted. Off by default to keep captures small.
	RecordOpaque bool

	// Debug logs every TLS connection that passes through without being
	// decrypted, and collects the hostnames for a summary at shutdown. It also
	// forces ClientHello inspection even when MITM is disabled, which is what
	// makes the hostnames available in the first place.
	Debug bool

	// DialTimeout bounds upstream connection attempts.
	DialTimeout time.Duration

	// UDPTimeout evicts idle UDP associations.
	UDPTimeout time.Duration

	Logf func(string, ...any)
}

// Server is a capturing SOCKS5 proxy.
type Server struct {
	opt Options
	w   *tapfile.Writer

	advertiseIP   net.IP
	advertisePort int

	ln   net.Listener
	wg   sync.WaitGroup
	quit chan struct{}
	once sync.Once

	skippedMu sync.Mutex
	skipped   map[string]int
}

// SkippedHost is one hostname that was tunnelled rather than decrypted.
type SkippedHost struct {
	Host  string // SNI, or a placeholder when there was none
	Conns int
}

// New creates a server that writes captured traffic to w.
func New(opt Options, w *tapfile.Writer) (*Server, error) {
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 15 * time.Second
	}
	if opt.UDPTimeout == 0 {
		opt.UDPTimeout = 5 * time.Minute
	}
	if opt.Logf == nil {
		opt.Logf = log.Printf
	}
	s := &Server{opt: opt, w: w, quit: make(chan struct{}), skipped: map[string]int{}}

	ip, err := resolveAdvertise(opt.Advertise)
	if err != nil {
		return nil, err
	}
	s.advertiseIP = ip
	return s, nil
}

// AdvertiseIP reports the address handed to clients for UDP relay.
func (s *Server) AdvertiseIP() net.IP { return s.advertiseIP }

// noteSkipped counts a connection that was not decrypted.
func (s *Server) noteSkipped(host string) {
	s.skippedMu.Lock()
	s.skipped[host]++
	s.skippedMu.Unlock()
}

// SkippedHosts returns the hostnames seen but not decrypted, busiest first.
//
// This is the list to consult when deciding what to add to -mitm.
func (s *Server) SkippedHosts() []SkippedHost {
	s.skippedMu.Lock()
	out := make([]SkippedHost, 0, len(s.skipped))
	for h, n := range s.skipped {
		out = append(out, SkippedHost{Host: h, Conns: n})
	}
	s.skippedMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// resolveAdvertise picks the address to advertise for UDP relay.
func resolveAdvertise(explicit string) (net.IP, error) {
	if explicit != "" {
		ip := net.ParseIP(explicit)
		if ip == nil {
			return nil, fmt.Errorf("socks: -advertise %q is not an IP", explicit)
		}
		return ip, nil
	}
	// Ask the kernel which local address it would use to reach the internet.
	// No packets are sent; this only consults the routing table.
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("socks: cannot auto-detect an advertise address, pass -advertise: %w", err)
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsLoopback() {
		return nil, errors.New("socks: auto-detected a loopback address; pass -advertise with the LAN IP")
	}
	return ip, nil
}

// ListenAndServe accepts connections until Close is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.opt.Listen)
	if err != nil {
		return err
	}
	s.ln = ln
	s.advertisePort = ln.Addr().(*net.TCPAddr).Port

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				s.wg.Wait()
				return nil
			default:
			}
			if mitm.IsBenignNetErr(err) {
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(c)
		}()
	}
}

// Addr reports the bound listener address, valid after ListenAndServe starts.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops accepting and waits for in-flight connections.
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.quit)
		if s.ln != nil {
			err = s.ln.Close()
		}
	})
	return err
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()

	if err := s.handshake(c); err != nil {
		if !mitm.IsBenignNetErr(err) {
			s.opt.Logf("socks: handshake from %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	cmd, dst, err := s.readRequest(c)
	if err != nil {
		if !mitm.IsBenignNetErr(err) {
			s.opt.Logf("socks: request from %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	switch cmd {
	case cmdConnect:
		s.handleConnect(c, dst)
	case cmdUDPAssociate:
		s.handleUDPAssociate(c)
	default:
		reply(c, repCmdNotSupported, net.IPv4zero, 0)
	}
}

// handshake performs method negotiation. Only no-auth is offered.
func (s *Server) handshake(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != ver5 {
		return fmt.Errorf("unsupported socks version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == methodNoAuth {
			_, err := c.Write([]byte{ver5, methodNoAuth})
			return err
		}
	}
	c.Write([]byte{ver5, methodNoAcceptable})
	return errors.New("client offered no acceptable auth method")
}

// target is a requested destination.
type target struct {
	host string // literal IP or domain name
	port int
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

// readRequest parses the SOCKS5 request that follows the handshake.
func (s *Server) readRequest(c net.Conn) (byte, target, error) {
	var t target
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, t, err
	}
	if head[0] != ver5 {
		return 0, t, fmt.Errorf("unsupported socks version %d", head[0])
	}
	cmd := head[1]

	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, t, err
		}
		t.host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, t, err
		}
		t.host = net.IP(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return 0, t, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, t, err
		}
		t.host = string(b)
	default:
		reply(c, repAtypNotSupported, net.IPv4zero, 0)
		return 0, t, fmt.Errorf("unsupported address type %d", head[3])
	}

	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return 0, t, err
	}
	t.port = int(binary.BigEndian.Uint16(pb[:]))
	return cmd, t, nil
}

// reply writes a SOCKS5 reply carrying a bound address.
func reply(c net.Conn, code byte, ip net.IP, port int) error {
	b := []byte{ver5, code, 0x00}
	if v4 := ip.To4(); v4 != nil {
		b = append(b, atypIPv4)
		b = append(b, v4...)
	} else if v6 := ip.To16(); v6 != nil {
		b = append(b, atypIPv6)
		b = append(b, v6...)
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	b = append(b, pb[:]...)
	_, err := c.Write(b)
	return err
}

// flowRecorder adapts a tapfile.Writer to the mitm.Recorder interface.
type flowRecorder struct {
	w      *tapfile.Writer
	flowID uint32
}

func (r flowRecorder) Data(dir uint8, b []byte) {
	if err := r.w.Data(r.flowID, dir, b); err != nil {
		r.w.NoteDrop()
	}
}
