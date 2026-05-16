package estclient

import (
	"crypto/x509"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// ExtractCertificates extracts certificates from a PKCS#7 DER encoded bundle.
func ExtractCertificates(der []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	var certs []*x509.Certificate
	for _, cert := range p7.Certificates {
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS#7 bundle")
	}

	return certs, nil
}
