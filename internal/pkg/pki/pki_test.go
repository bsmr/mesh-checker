package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateCAProducesValidSelfSignedCert(t *testing.T) {
	ca, err := GenerateCA("mesh-checker test CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert not marked IsCA")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert missing KeyUsageCertSign")
	}
	if ca.PrivateKey == nil {
		t.Error("CA private key is nil")
	}
}

func TestGenerateHostCertSignedByCA(t *testing.T) {
	ca, err := GenerateCA("CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	host, err := GenerateHostCert(ca, "node-a", []string{"10.0.0.1"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := host.Cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("host cert did not verify against CA: %v", err)
	}
	if host.Cert.Subject.CommonName != "node-a" {
		t.Errorf("CN = %q, want node-a", host.Cert.Subject.CommonName)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	ca, _ := GenerateCA("CA", 24*time.Hour)
	certPEM, keyPEM, err := Encode(ca)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if back.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Error("serial mismatch after round-trip")
	}
}
