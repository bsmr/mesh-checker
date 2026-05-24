// Package pki creates and loads the mesh-checker mTLS PKI material:
// one Ed25519 Mesh CA and one host cert per node, with Server+Client EKU.
// No file I/O lives here; encoding is PEM-in-memory.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Material is a cert + the private key that signs/owns it.
type Material struct {
	Cert       *x509.Certificate
	DERCert    []byte
	PrivateKey ed25519.PrivateKey
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// GenerateCA returns a self-signed CA valid for the given lifetime.
func GenerateCA(commonName string, lifetime time.Duration) (*Material, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: cert, DERCert: der, PrivateKey: priv}, nil
}

// GenerateHostCert signs a host cert with Server+Client EKU under ca.
// hostName becomes the CN; sans are added as DNS or IP SANs.
func GenerateHostCert(ca *Material, hostName string, sans []string, lifetime time.Duration) (*Material, error) {
	if ca == nil || ca.PrivateKey == nil {
		return nil, errors.New("pki: ca material missing private key")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostName},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Material{Cert: cert, DERCert: der, PrivateKey: priv}, nil
}

// Encode returns PEM-encoded cert and private key.
func Encode(m *Material) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.DERCert})
	keyDER, err := x509.MarshalPKCS8PrivateKey(m.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Decode parses PEM cert + key back into Material.
func Decode(certPEM, keyPEM []byte) (*Material, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pki: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	m := &Material{Cert: cert, DERCert: cb.Bytes}
	if keyPEM != nil {
		kb, _ := pem.Decode(keyPEM)
		if kb == nil || kb.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("pki: invalid key PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, err
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pki: key is not ed25519")
		}
		m.PrivateKey = edKey
	}
	return m, nil
}

// LoadCertOnly reads only the cert PEM (no key) — used by the daemon
// to load the CA bundle without touching the CA private key.
func LoadCertOnly(certPEM []byte) (*Material, error) {
	return Decode(certPEM, nil)
}
