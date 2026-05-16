package estclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// oidChallengePassword is the ASN.1 OID for the challengePassword attribute
// as defined in RFC 2985 (PKCS #9). This is used by RFC 7030 Section 3.5
// for tls-unique channel binding.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// GenerateCSR creates a PKCS#10 CSR with the given common name, tls-unique
// channel binding value, and CSR attributes from the EST portal.
//
// Per RFC 7030 Section 3.5, the tls-unique channel binding value is placed
// in the challengePassword attribute of the CSR.
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

	// RFC 7030 Section 3.5: Place the tls-unique channel binding value
	// in the challengePassword attribute of the CSR.
	if len(tlsUnique) > 0 {
		template.Attributes = []pkix.AttributeTypeAndValueSET{
			{
				Type: oidChallengePassword,
				Value: [][]pkix.AttributeTypeAndValue{
					{
						{
							Type:  oidChallengePassword,
							Value: string(tlsUnique),
						},
					},
				},
			},
		}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Note: attributes from the EST portal's /csrattrs endpoint would be
	// integrated here as extension requests if the portal returned them.
	// For now, the raw attributes bytes are available for future integration.

	return csrBytes, priv, nil
}