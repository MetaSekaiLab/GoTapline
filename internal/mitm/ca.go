// Package mitm terminates TLS for an allowlisted set of SNI names so the
// plaintext can be recorded, and leaves every other connection untouched.
//
// Selectivity is the point: certificate-pinned hosts must keep seeing their
// real server certificate or the app breaks, so only names the operator names
// explicitly are intercepted.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA mints short-lived leaf certificates for intercepted hostnames.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte

	mu    sync.Mutex
	cache map[string]*tlsCertPair
}

type tlsCertPair struct {
	der [][]byte
	key *ecdsa.PrivateKey
	exp time.Time
}

// LoadOrCreateCA reads a CA from dir, generating one on first use.
//
// The CA is written as ca.pem / ca.key.pem, and ca.pem is what gets installed
// and trusted on the capturing device.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key.pem")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		if err == nil {
			return ca, nil
		}
		// fall through and regenerate rather than fail a capture run
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "GoTapline Capture CA",
			Organization: []string{"GoTapline"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: der, cache: map[string]*tlsCertPair{}}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("mitm: malformed CA files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("mitm: CA expired")
	}
	return &CA{cert: cert, key: key, der: cb.Bytes, cache: map[string]*tlsCertPair{}}, nil
}

// CertPath returns where the installable CA certificate lives.
func CertPath(dir string) string { return filepath.Join(dir, "ca.pem") }

// Fingerprint is the SHA-256 of the CA certificate, for verifying that the
// device trusted the right one.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.der)
	return hex.EncodeToString(sum[:])
}

// Subject renders the CA subject for display.
func (c *CA) Subject() string { return c.cert.Subject.CommonName }

// leafFor returns a certificate chain for host, minting and caching on demand.
func (c *CA) leafFor(host string) (*tlsCertPair, error) {
	c.mu.Lock()
	if p, ok := c.cache[host]; ok && time.Now().Before(p.exp) {
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	notAfter := time.Now().AddDate(0, 6, 0)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// iOS requires the name in a SAN; CommonName alone is not accepted.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	pair := &tlsCertPair{der: [][]byte{der, c.der}, key: key, exp: notAfter.Add(-24 * time.Hour)}

	c.mu.Lock()
	c.cache[host] = pair
	c.mu.Unlock()
	return pair, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
