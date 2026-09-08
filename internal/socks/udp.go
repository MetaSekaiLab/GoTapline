package socks

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"gotapline/internal/mitm"
	"gotapline/internal/tapfile"
)

// maxDatagram bounds a single relayed datagram. Diarkis caps its own packets
// at 1300 bytes, but allow a full jumbo-ish read so nothing is silently cut.
const maxDatagram = 65535

// udpSession is one UDP ASSOCIATE: a relay socket plus the flows seen on it.
type udpSession struct {
	srv  *Server
	pc   *net.UDPConn
	ctrl net.Conn // the TCP control connection; its close tears us down

	mu       sync.Mutex
	client   *net.UDPAddr            // learned from the first datagram
	flows    map[string]uint32       // destination -> flowID
	upstream map[string]*net.UDPConn // destination -> socket used to reach it
	lastSeen time.Time
}

// handleUDPAssociate sets up a relay socket, tells the client where to send,
// and services datagrams until the control connection closes.
func (s *Server) handleUDPAssociate(ctrl net.Conn) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		reply(ctrl, repGeneralFailure, net.IPv4zero, 0)
		s.opt.Logf("socks: udp listen: %v", err)
		return
	}
	defer pc.Close()

	port := pc.LocalAddr().(*net.UDPAddr).Port

	// Advertise an address the device can actually reach. Handing back the
	// listener's 0.0.0.0, or a loopback address, is what silently breaks UDP
	// relay for a remote client.
	if err := reply(ctrl, repSuccess, s.advertiseIP, port); err != nil {
		return
	}
	s.opt.Logf("udp   associate for %s -> relay %s:%d", ctrl.RemoteAddr(), s.advertiseIP, port)

	sess := &udpSession{
		srv:      s,
		pc:       pc,
		ctrl:     ctrl,
		flows:    map[string]uint32{},
		upstream: map[string]*net.UDPConn{},
		lastSeen: time.Now(),
	}
	defer sess.closeAll()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.readFromClient()
	}()

	// Per RFC 1928 the association lives as long as the TCP control connection,
	// so draining it to EOF is how we learn the client is finished.
	io.Copy(io.Discard, ctrl)
	pc.SetReadDeadline(time.Now())
	<-done
}

// readFromClient handles datagrams arriving from the device.
func (s *udpSession) readFromClient() {
	buf := make([]byte, maxDatagram)
	for {
		s.pc.SetReadDeadline(time.Now().Add(s.srv.opt.UDPTimeout))
		n, from, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return
			}
			return
		}

		dstHost, dstPort, payload, perr := parseUDPRequest(buf[:n])
		if perr != nil {
			s.srv.w.NoteDrop()
			continue
		}

		s.mu.Lock()
		if s.client == nil {
			s.client = from
		}
		s.lastSeen = time.Now()
		s.mu.Unlock()

		dst := net.JoinHostPort(dstHost, strconv.Itoa(dstPort))
		fid, uc := s.flowFor(dst, from)
		if uc == nil {
			continue
		}
		if err := s.srv.w.Data(fid, tapfile.DirC2S, payload); err != nil {
			s.srv.w.NoteDrop()
		}
		if _, err := uc.Write(payload); err != nil && !mitm.IsBenignNetErr(err) {
			s.srv.opt.Logf("udp   send to %s: %v", dst, err)
		}
	}
}

// flowFor returns the tapfile flow and upstream socket for a destination,
// creating both (and a reader goroutine) on first use.
func (s *udpSession) flowFor(dst string, from *net.UDPAddr) (uint32, *net.UDPConn) {
	s.mu.Lock()
	if fid, ok := s.flows[dst]; ok {
		uc := s.upstream[dst]
		s.mu.Unlock()
		return fid, uc
	}
	s.mu.Unlock()

	ua, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		s.srv.w.NoteDrop()
		return 0, nil
	}
	uc, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		s.srv.opt.Logf("udp   dial %s: %v", dst, err)
		s.srv.w.NoteDrop()
		return 0, nil
	}
	fid, err := s.srv.w.FlowOpen(tapfile.FlowOpen{
		Proto:  tapfile.ProtoUDP,
		Mode:   tapfile.ModeRaw,
		Client: from.String(),
		Remote: dst,
	})
	if err != nil {
		uc.Close()
		s.srv.opt.Logf("socks: tapfile: %v", err)
		return 0, nil
	}

	s.mu.Lock()
	// Another datagram may have raced us here.
	if existing, ok := s.flows[dst]; ok {
		s.mu.Unlock()
		uc.Close()
		return existing, s.upstream[dst]
	}
	s.flows[dst] = fid
	s.upstream[dst] = uc
	s.mu.Unlock()

	s.srv.opt.Logf("udp   flow %d  %s -> %s", fid, from, dst)
	go s.readFromUpstream(dst, fid, uc, ua)
	return fid, uc
}

// readFromUpstream relays replies back to the device, re-wrapping them in the
// SOCKS5 UDP header the client expects.
func (s *udpSession) readFromUpstream(dst string, fid uint32, uc *net.UDPConn, ua *net.UDPAddr) {
	defer uc.Close()
	buf := make([]byte, maxDatagram)
	for {
		uc.SetReadDeadline(time.Now().Add(s.srv.opt.UDPTimeout))
		n, err := uc.Read(buf)
		if n > 0 {
			if werr := s.srv.w.Data(fid, tapfile.DirS2C, buf[:n]); werr != nil {
				s.srv.w.NoteDrop()
			}
			s.mu.Lock()
			client := s.client
			s.lastSeen = time.Now()
			s.mu.Unlock()
			if client != nil {
				out := buildUDPReply(ua, buf[:n])
				if _, werr := s.pc.WriteToUDP(out, client); werr != nil && !mitm.IsBenignNetErr(werr) {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *udpSession) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for dst, uc := range s.upstream {
		uc.Close()
		if fid, ok := s.flows[dst]; ok {
			s.srv.w.FlowClose(fid)
		}
	}
	s.upstream = map[string]*net.UDPConn{}
}

// parseUDPRequest strips the SOCKS5 UDP header:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
//
// Fragmented datagrams (FRAG != 0) are rejected; no real client uses them and
// silently reassembling would corrupt the capture.
func parseUDPRequest(b []byte) (host string, port int, payload []byte, err error) {
	if len(b) < 5 {
		return "", 0, nil, errors.New("short udp request")
	}
	if b[2] != 0x00 {
		return "", 0, nil, errors.New("fragmented udp datagram")
	}
	i := 4
	switch b[3] {
	case atypIPv4:
		if len(b) < i+4 {
			return "", 0, nil, errors.New("short ipv4")
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case atypIPv6:
		if len(b) < i+16 {
			return "", 0, nil, errors.New("short ipv6")
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case atypDomain:
		if len(b) < i+1 {
			return "", 0, nil, errors.New("short domain")
		}
		l := int(b[i])
		i++
		if len(b) < i+l {
			return "", 0, nil, errors.New("short domain body")
		}
		host = string(b[i : i+l])
		i += l
	default:
		return "", 0, nil, errors.New("bad atyp")
	}
	if len(b) < i+2 {
		return "", 0, nil, errors.New("short port")
	}
	port = int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	return host, port, b[i:], nil
}

// buildUDPReply wraps a payload in the SOCKS5 UDP header.
func buildUDPReply(from *net.UDPAddr, payload []byte) []byte {
	var head []byte
	if v4 := from.IP.To4(); v4 != nil {
		head = make([]byte, 0, 10+len(payload))
		head = append(head, 0, 0, 0, atypIPv4)
		head = append(head, v4...)
	} else {
		head = make([]byte, 0, 22+len(payload))
		head = append(head, 0, 0, 0, atypIPv6)
		head = append(head, from.IP.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(from.Port))
	head = append(head, pb[:]...)
	return append(head, payload...)
}
