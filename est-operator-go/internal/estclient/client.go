package estclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Config defines the configuration for the EST client.
type Config struct {
	Host    string
	Port    int
	CACerts []byte // PEM encoded trusted root certificates
	Scheme  string // "http" or "https", defaults to "https"
	Username string // For Basic Auth
	Password string // For Basic Auth
	Cert    []byte // PEM encoded client certificate
	Key     []byte // PEM encoded client private key
}

// Client defines the interface for the EST protocol client.
type Client interface {
	FetchCACerts(ctx context.Context) ([]byte, error)
	FetchCSRAttributes(ctx context.Context) ([]byte, error)
	SimpleEnroll(ctx context.Context, csr []byte) ([]byte, error)
	SimpleReenroll(ctx context.Context, csr []byte) ([]byte, error)
	GetTLSUnique(ctx context.Context) ([]byte, error)
	ExtractCertificates(bundle []byte) ([]*x509.Certificate, error)
}

// ClientFactory defines an interface for creating EST clients.
type ClientFactory interface {
	NewClient(cfg *Config) (Client, error)
}

type defaultClientFactory struct{}

// NewClientFactory returns a default implementation of ClientFactory.
func NewClientFactory() ClientFactory {
	return &defaultClientFactory{}
}

func (f *defaultClientFactory) NewClient(cfg *Config) (Client, error) {
	return NewClient(cfg)
}

type estClient struct {

	cfg    *Config
	httpClient *http.Client
}

// NewClient creates a new EST client.
func NewClient(cfg *Config) (Client, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("host is required")
	}

	tlsConfig := &tls.Config{
		ServerName: cfg.Host,
	}

	if len(cfg.Cert) > 0 && len(cfg.Key) > 0 {
		cert, err := tls.X509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &estClient{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}, nil
}

func (c *estClient) FetchCACerts(ctx context.Context) ([]byte, error) {
	url := c.buildURL("/cacerts")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from /cacerts: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// FetchCSRAttributes retrieves the CSR attribute requirements from the EST portal.
func (c *estClient) FetchCSRAttributes(ctx context.Context) ([]byte, error) {
	url := c.buildURL("/.well-known/est/csrattrs")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from /csrattrs: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SimpleEnroll performs an initial enrollment request using HTTP Basic Auth.
func (c *estClient) SimpleEnroll(ctx context.Context, csr []byte) ([]byte, error) {
	url := c.buildURL("/simpleenroll")

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(csr))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Content-Type to application/pkcs10
	req.Header.Set("Content-Type", "application/pkcs10")

	// Apply Basic Auth if configured
	if c.cfg.Username != "" || c.cfg.Password != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from /simpleenroll: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SimpleReenroll performs a renewal request using TLS client authentication.
func (c *estClient) SimpleReenroll(ctx context.Context, csr []byte) ([]byte, error) {
	url := c.buildURL("/simplereenroll")

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(csr))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/pkcs10")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from /simplereenroll: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (c *estClient) buildURL(path string) string {
	scheme := "https"
	if c.cfg.Scheme != "" {
		scheme = c.cfg.Scheme
	}
	host := c.cfg.Host
	port := c.cfg.Port

	if port == 0 {
		return fmt.Sprintf("%s://%s%s", scheme, host, path)
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
}

// GetTLSUnique performs a TLS handshake with the portal and extracts the tls-unique value.
func (c *estClient) GetTLSUnique(ctx context.Context) ([]byte, error) {
	address := c.cfg.Host
	if c.cfg.Port != 0 {
		address = fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName: c.cfg.Host,
	}
	
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	if state.TLSUnique == nil {
		return nil, fmt.Errorf("tls-unique not available in this connection")
	}

	return state.TLSUnique, nil
}

func (c *estClient) ExtractCertificates(bundle []byte) ([]*x509.Certificate, error) {
	return ExtractCertificates(bundle)
}
