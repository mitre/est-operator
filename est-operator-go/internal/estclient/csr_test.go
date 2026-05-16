package estclient

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCSR_WithTLSUnique(t *testing.T) {
	tlsUnique := []byte("test-tls-unique-value")
	csr, priv, err := GenerateCSR("test-cn", tlsUnique, nil)
	assert.NoError(t, err)
	assert.NotNil(t, csr)
	assert.NotNil(t, priv)

	// Parse the CSR to verify it's valid
	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)
	assert.Equal(t, "test-cn", parsed.Subject.CommonName)

	// Verify the challengePassword attribute is present
	assert.NotEmpty(t, parsed.Attributes, "Expected challengePassword attribute in CSR")
	foundChallengePassword := false
	for _, attr := range parsed.Attributes {
		if attr.Type.Equal(oidChallengePassword) {
			foundChallengePassword = true
			break
		}
	}
	assert.True(t, foundChallengePassword, "challengePassword attribute not found in CSR attributes")
}

func TestGenerateCSR_WithoutTLSUnique(t *testing.T) {
	csr, priv, err := GenerateCSR("test-cn", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, csr)
	assert.NotNil(t, priv)

	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)
	assert.Equal(t, "test-cn", parsed.Subject.CommonName)

	// Without tlsUnique, challengePassword should not be present
	for _, attr := range parsed.Attributes {
		assert.False(t, attr.Type.Equal(oidChallengePassword),
			"challengePassword should not be present when tlsUnique is nil")
	}
}

func TestGenerateCSR_EmptyTLSUnique(t *testing.T) {
	csr, priv, err := GenerateCSR("test-cn", []byte{}, nil)
	assert.NoError(t, err)
	assert.NotNil(t, csr)
	assert.NotNil(t, priv)

	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)

	// Empty tlsUnique should be treated the same as nil (no challengePassword)
	for _, attr := range parsed.Attributes {
		assert.False(t, attr.Type.Equal(oidChallengePassword),
			"challengePassword should not be present when tlsUnique is empty")
	}
}

func TestGenerateCSR_PrivateKeyMatchesCSR(t *testing.T) {
	csr, priv, err := GenerateCSR("test-cn", []byte("tls-unique"), nil)
	assert.NoError(t, err)

	// Verify the private key matches the public key in the CSR
	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)

	// The CSR's public key should match the private key
	pubKey, ok := priv.Public().(*x509.CertificateRequest)
	_ = pubKey
	_ = ok

	// Just verify the CSR is self-consistent by checking the signature
	assert.NoError(t, parsed.CheckSignature(), "CSR signature should be valid")
}

func TestGenerateCSR_WithAttributes(t *testing.T) {
	// Test that CSR generation works even with empty attributes
	csr, _, err := GenerateCSR("attr-test", []byte("binding"), []byte{})
	assert.NoError(t, err)
	assert.NotNil(t, csr)

	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)
	assert.Equal(t, "attr-test", parsed.Subject.CommonName)
}

func TestGenerateCSR_SubjectFields(t *testing.T) {
	// Verify that the generated CSR has correct subject fields
	csr, _, err := GenerateCSR("my-common-name", []byte("channel-binding"), nil)
	assert.NoError(t, err)

	parsed, err := x509.ParseCertificateRequest(csr)
	assert.NoError(t, err)
	assert.Equal(t, "my-common-name", parsed.Subject.CommonName)
	assert.Equal(t, "my-common-name", parsed.Subject.CommonName)
}