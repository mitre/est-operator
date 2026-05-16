package estclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestFetchCACerts(t *testing.T) {
	expectedCerts := []byte("mock-cacerts")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cacerts" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(expectedCerts)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	host := u.Hostname()
	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)

	cfg := &Config{
		Host:   host,
		Port:   port,
		Scheme: "http",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// We must override the httpClient because NewClient uses a transport with TLS
	// and httptest.NewServer is plain HTTP.
	estClient := client.(*estClient)
	estClient.httpClient = ts.Client()

	certs, err := client.FetchCACerts(context.Background())
	if err != nil {
		t.Fatalf("FetchCACerts failed: %v", err)
	}

	if string(certs) != string(expectedCerts) {
		t.Errorf("expected %s, got %s", string(expectedCerts), string(certs))
	}
}
