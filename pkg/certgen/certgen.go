// Package certgen manages the DarkObscura root CA and mints leaf certificates
// on demand for TLS MITM interception. A single root CA is persisted to disk and
// reused across runs; leaf certs are generated per-SNI and cached in memory.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA holds the root certificate authority and an in-memory cache of leaf
// certificates keyed by the requested server name (SNI/host).
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// leafTTL is how long minted leaf certificates remain valid.
const leafTTL = 90 * 24 * time.Hour

// LoadOrCreate loads the root CA from dir (ca.crt / ca.key). If either file is
// missing it generates a fresh CA and persists it with 0600 permissions on the key.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("certgen: mkdir %s: %w", dir, err)
	}
	crtPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	crtPEM, crtErr := os.ReadFile(crtPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if crtErr == nil && keyErr == nil {
		ca, err := parseCA(crtPEM, keyPEM)
		if err == nil {
			return ca, nil
		}
		// Fall through and regenerate on a corrupt/unreadable CA.
	}

	ca, crtOut, keyOut, err := generateCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(crtPath, crtOut, 0o644); err != nil {
		return nil, fmt.Errorf("certgen: write ca.crt: %w", err)
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, fmt.Errorf("certgen: write ca.key: %w", err)
	}
	return ca, nil
}

func parseCA(crtPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(crtPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certgen: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("certgen: invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: crtPEM, cache: map[string]*tls.Certificate{}}, nil
}

func generateCA() (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "DarkObscura Root CA",
			Organization: []string{"DarkObscura"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{cert: cert, key: key, certPEM: crtPEM, cache: map[string]*tls.Certificate{}}, crtPEM, keyPEM, nil
}

// CertPEM returns the PEM-encoded root certificate so the user can trust it.
func (c *CA) CertPEM() []byte { return c.certPEM }

// LeafForName returns a TLS certificate valid for the given host, minting and
// caching one signed by the root CA if not already present.
func (c *CA) LeafForName(host string) (*tls.Certificate, error) {
	host = stripPort(host)
	c.mu.RLock()
	if cert, ok := c.cache[host]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	cert, err := c.mintLeaf(host)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cache[host] = cert
	c.mu.Unlock()
	return cert, nil
}

func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
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
		Subject:      pkix.Name{CommonName: host, Organization: []string{"DarkObscura MITM"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        tmpl,
	}, nil
}

// TLSConfig returns a *tls.Config whose GetCertificate mints leaves per-SNI,
// suitable for wrapping an intercepted CONNECT tunnel.
func (c *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = stripPort(hello.Conn.LocalAddr().String())
			}
			return c.LeafForName(name)
		},
	}
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
