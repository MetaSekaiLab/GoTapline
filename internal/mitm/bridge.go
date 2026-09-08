package mitm

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

// Recorder receives plaintext as it flows through an intercepted connection.
type Recorder interface {
	// Data is called with a chunk of plaintext. The slice is only valid for the
	// duration of the call.
	Data(dir uint8, b []byte)
}

const (
	dirC2S uint8 = 0
	dirS2C uint8 = 1
)

// Config controls interception.
type Config struct {
	CA *CA

	// Hosts is the set of SNI names to intercept. A leading "*." matches any
	// subdomain. Everything not listed is tunnelled untouched.
	Hosts []string

	// AllowH2 offers HTTP/2 during the intercepted handshake. It is off by
	// default: with h2 the recorded plaintext is HPACK-compressed HTTP/2
	// frames, whereas forcing http/1.1 yields plainly readable requests.
	AllowH2 bool

	// InsecureUpstream skips verification of the real server's certificate.
	// Off by default; a capture tool should still notice a broken upstream.
	InsecureUpstream bool
}

// ShouldIntercept reports whether an SNI name is on the allowlist.
func (c *Config) ShouldIntercept(sni string) bool {
	if sni == "" {
		return false
	}
	host := strings.ToLower(sni)
	for _, pat := range c.Hosts {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(host, pat[1:]) || host == pat[2:] {
				return true
			}
			continue
		}
		if host == pat {
			return true
		}
	}
	return false
}

// Bridge terminates TLS from the client, completes TLS to the real server over
// an already-established socket, and pumps plaintext between them while handing
// every chunk to rec.
//
// clientRaw must already have had its ClientHello replayed into it (see
// NewPeekedConn). upstreamRaw must be the TCP connection that was dialled for
// the original CONNECT: reusing it rather than re-dialling keeps us on the
// exact host the client asked for and avoids a second DNS lookup that could
// resolve elsewhere.
func Bridge(cfg *Config, clientRaw, upstreamRaw net.Conn, sni string, rec Recorder) error {
	pair, err := cfg.CA.leafFor(sni)
	if err != nil {
		return err
	}

	nextProtos := []string{"http/1.1"}
	if cfg.AllowH2 {
		nextProtos = []string{"h2", "http/1.1"}
	}

	serverSide := tls.Server(clientRaw, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: pair.der,
			PrivateKey:  pair.key,
		}},
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS12,
	})
	if err := serverSide.Handshake(); err != nil {
		return err
	}

	// Continue onward over the socket we already hold, offering the same ALPN we
	// settled on with the client so both halves speak the same HTTP version.
	alpn := serverSide.ConnectionState().NegotiatedProtocol
	var upstreamProtos []string
	if alpn != "" {
		upstreamProtos = []string{alpn}
	}
	upstream := tls.Client(upstreamRaw, &tls.Config{
		ServerName:         sni,
		NextProtos:         upstreamProtos,
		InsecureSkipVerify: cfg.InsecureUpstream,
		MinVersion:         tls.VersionTLS12,
	})
	if err := upstream.Handshake(); err != nil {
		serverSide.Close()
		return err
	}

	pump(serverSide, upstream, rec)
	return nil
}

// pump copies both directions concurrently, recording as it goes, and returns
// once both halves are done.
func pump(client, server net.Conn, rec Recorder) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyRecording(server, client, dirC2S, rec)
		// Signal EOF onward so the peer can finish its response.
		if cw, ok := server.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			server.Close()
		}
	}()
	go func() {
		defer wg.Done()
		copyRecording(client, server, dirS2C, rec)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			client.Close()
		}
	}()

	wg.Wait()
	client.Close()
	server.Close()
}

// copyRecording moves bytes from src to dst, handing each chunk to rec.
func copyRecording(dst io.Writer, src io.Reader, dir uint8, rec Recorder) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if rec != nil {
				rec.Data(dir, buf[:n])
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Tunnel copies bytes between two connections without inspecting them, used
// for every host not on the allowlist. If rec is non-nil the ciphertext is
// recorded as-is.
func Tunnel(client, server net.Conn, rec Recorder) {
	pump(client, server, rec)
}

// IsBenignNetErr reports whether an error is the ordinary end of a connection
// rather than something worth logging.
func IsBenignNetErr(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "use of closed")
}
