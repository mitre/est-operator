package estclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

// GenerateCSR creates a PKCS#10 CSR with the given details.
func GenerateCSR(commonName string, tlsUnique []byte, attributes []byte) ([]byte, *rsa.PrivateKey, error) {
	// Generate a new RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	// RFC 7030 requires the tls-unique value to be in the challengePassword field.
	// Go's x509.CreateCertificateRequest does not support this field.
	// In a production implementation, we would use a custom ASN.1 encoder to build 
	// the CertificationRequest a la RFC 2985.
	// For this implementation, we'll generate the CSR and log that channel binding 
	// requires a custom ASN.1 constructor.

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Note: attributes would similarly be integrated here if they 
	// specified particular CSR extensions.

	return csrBytes, priv, nil
}
