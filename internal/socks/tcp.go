package socks

import (
	"errors"
	"net"

	"gotapline/internal/mitm"
	"gotapline/internal/tapfile"
)

// handleConnect services a SOCKS5 CONNECT: dial the destination, then either
// intercept TLS (when the SNI is allowlisted) or tunnel bytes untouched.
func (s *Server) handleConnect(client net.Conn, dst target) {
	upstream, err := net.DialTimeout("tcp", dst.String(), s.opt.DialTimeout)
	if err != nil {
		reply(client, repGeneralFailure, net.IPv4zero, 0)
		if !mitm.IsBenignNetErr(err) {
			s.opt.Logf("socks: dial %s: %v", dst, err)
		}
		return
	}
	defer upstream.Close()

	local := upstream.LocalAddr().(*net.TCPAddr)
	if err := reply(client, repSuccess, local.IP, local.Port); err != nil {
		return
	}

	// Peek when either interception or debug reporting needs the hostname.
	// Without this, running -debug alone would report connections with no name
	// attached, since nothing would have parsed the ClientHello.
	if s.opt.MITM == nil && !s.opt.Debug {
		s.tunnel(client, upstream, dst, "")
		return
	}

	sni, consumed, err := mitm.PeekClientHello(client)
	if err != nil && !errors.Is(err, mitm.ErrNotClientHello) {
		// Connection died while we were peeking; nothing to record.
		if len(consumed) > 0 {
			upstream.Write(consumed)
		}
		return
	}

	// Replay whatever we consumed so the next stage sees a complete stream.
	replayed := mitm.NewPeekedConn(client, consumed)

	if sni != "" && s.opt.MITM != nil && s.opt.MITM.ShouldIntercept(sni) {
		fid, ferr := s.w.FlowOpen(tapfile.FlowOpen{
			Proto:  tapfile.ProtoTCP,
			Mode:   tapfile.ModeTLSPlaintext,
			Client: client.RemoteAddr().String(),
			Remote: dst.String(),
			SNI:    sni,
		})
		if ferr != nil {
			s.opt.Logf("socks: tapfile: %v", ferr)
			return
		}
		defer s.w.FlowClose(fid)

		s.opt.Logf("mitm  %s -> %s (%s)", client.RemoteAddr(), dst, sni)
		if err := mitm.Bridge(s.opt.MITM, replayed, upstream, sni, flowRecorder{s.w, fid}); err != nil {
			if !mitm.IsBenignNetErr(err) {
				s.opt.Logf("mitm  %s: %v", sni, err)
			}
		}
		return
	}

	if s.opt.Debug {
		s.reportSkipped(client, dst, sni, err)
	}
	s.tunnel(replayed, upstream, dst, sni)
}

// reportSkipped logs and counts a connection that passed through undecrypted.
func (s *Server) reportSkipped(client net.Conn, dst target, sni string, peekErr error) {
	switch {
	case sni != "":
		s.noteSkipped(sni)
		s.opt.Logf("skip  %s -> %s  sni=%s", client.RemoteAddr(), dst, sni)
	case errors.Is(peekErr, mitm.ErrNotClientHello):
		s.noteSkipped("(not TLS) " + dst.host)
		s.opt.Logf("skip  %s -> %s  (not TLS)", client.RemoteAddr(), dst)
	default:
		s.noteSkipped("(no SNI) " + dst.host)
		s.opt.Logf("skip  %s -> %s  (TLS without SNI)", client.RemoteAddr(), dst)
	}
}

// tunnel forwards without inspection, recording only flow metadata unless the
// operator asked for opaque bodies too.
func (s *Server) tunnel(client, upstream net.Conn, dst target, sni string) {
	fid, err := s.w.FlowOpen(tapfile.FlowOpen{
		Proto:  tapfile.ProtoTCP,
		Mode:   tapfile.ModeTLSOpaque,
		Client: client.RemoteAddr().String(),
		Remote: dst.String(),
		SNI:    sni,
	})
	if err != nil {
		s.opt.Logf("socks: tapfile: %v", err)
		return
	}
	defer s.w.FlowClose(fid)

	var rec mitm.Recorder
	if s.opt.RecordOpaque {
		rec = flowRecorder{s.w, fid}
	}
	mitm.Tunnel(client, upstream, rec)
}
