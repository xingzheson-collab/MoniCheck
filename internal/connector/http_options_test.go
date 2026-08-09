package connector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthTransportSetsCredentialHeaders(t *testing.T) {
	transport := authTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer token" {
				t.Fatalf("expected bearer token header, got %q", req.Header.Get("Authorization"))
			}
			if req.Header.Get("X-API-Key") != "api-key" {
				t.Fatalf("expected api key header, got %q", req.Header.Get("X-API-Key"))
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
		options: HTTPOptions{BearerToken: "token", APIKey: "api-key"},
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestAuthTransportUsesBasicAuthAndBearerPrecedence(t *testing.T) {
	checks := []struct {
		name     string
		options  HTTPOptions
		expected string
	}{
		{name: "basic", options: HTTPOptions{Username: "reader", Password: "private-password"}, expected: "Basic cmVhZGVyOnByaXZhdGUtcGFzc3dvcmQ="},
		{name: "bearer precedence", options: HTTPOptions{BearerToken: "token", Username: "reader", Password: "private-password"}, expected: "Bearer token"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			transport := authTransport{
				base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if got := req.Header.Get("Authorization"); got != check.expected {
						t.Fatalf("expected authorization %q, got %q", check.expected, got)
					}
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
				}),
				options: check.options,
			}
			req, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
			if _, err := transport.RoundTrip(req); err != nil {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

func TestNewHTTPClientUsesTLSOptions(t *testing.T) {
	client, err := NewHTTPClient(HTTPOptions{InsecureSkipVerify: true, Timeout: time.Second})
	if err != nil {
		t.Fatalf("new http client: %v", err)
	}
	if client.Timeout != time.Second {
		t.Fatalf("expected timeout %s, got %s", time.Second, client.Timeout)
	}
	transport, ok := client.Transport.(authTransport)
	if !ok {
		t.Fatalf("expected auth transport, got %T", client.Transport)
	}
	retry, ok := transport.base.(retryTransport)
	if !ok {
		t.Fatalf("expected retry transport, got %T", transport.base)
	}
	if retry.maxRetries != defaultConnectorMaxRetries {
		t.Fatalf("expected %d retries, got %d", defaultConnectorMaxRetries, retry.maxRetries)
	}
	base, ok := retry.base.(*http.Transport)
	if !ok {
		t.Fatalf("expected http transport, got %T", retry.base)
	}
	if base.TLSClientConfig == nil || !base.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify TLS config")
	}
}

func TestNewHTTPClientLoadsMutualTLSCertificate(t *testing.T) {
	certFile, keyFile, _ := writeTestClientCertificate(t)
	client, err := NewHTTPClient(HTTPOptions{ClientCertFile: certFile, ClientKeyFile: keyFile})
	if err != nil {
		t.Fatalf("new mTLS client: %v", err)
	}
	transport := client.Transport.(authTransport).base.(retryTransport).base.(*http.Transport)
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatal("expected one configured TLS client certificate")
	}
}

func TestNewHTTPClientCompletesMutualTLSHandshake(t *testing.T) {
	certFile, keyFile, clientCertPEM := writeTestClientCertificate(t)
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(clientCertPEM) {
		t.Fatal("append client certificate")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	server.StartTLS()
	defer server.Close()

	serverCAFile := filepath.Join(t.TempDir(), "server-ca.pem")
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(serverCAFile, serverCertPEM, 0o600); err != nil {
		t.Fatalf("write server CA: %v", err)
	}
	withoutClientCert, err := NewHTTPClient(HTTPOptions{CAFile: serverCAFile, MaxRetries: -1})
	if err != nil {
		t.Fatalf("new CA-only client: %v", err)
	}
	if _, err := withoutClientCert.Get(server.URL); err == nil {
		t.Fatal("server accepted a request without the required client certificate")
	}
	client, err := NewHTTPClient(HTTPOptions{CAFile: serverCAFile, ClientCertFile: certFile, ClientKeyFile: keyFile, MaxRetries: -1})
	if err != nil {
		t.Fatalf("new mTLS client: %v", err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected mTLS success, got %s", response.Status)
	}
}

func TestNewHTTPClientRejectsIncompleteMutualTLSConfiguration(t *testing.T) {
	for _, options := range []HTTPOptions{{ClientCertFile: "client.crt"}, {ClientKeyFile: "client.key"}} {
		if _, err := NewHTTPClient(options); err == nil || !strings.Contains(err.Error(), "configured together") {
			t.Fatalf("expected incomplete mTLS configuration error, got %v", err)
		}
	}
}

func writeTestClientCertificate(t *testing.T) (string, string, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "monicheck-test-client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "client.crt")
	keyFile := filepath.Join(directory, "client.key")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile, certificatePEM
}

func TestRetryTransportRetriesTransientResponsesAndClosesBodies(t *testing.T) {
	var attempts int
	var closed atomic.Int32
	transport := retryTransport{
		maxRetries: 2,
		backoff:    time.Millisecond,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts < 3 {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header:     http.Header{"Retry-After": []string{"0"}},
					Body:       &trackingReadCloser{Reader: strings.NewReader("retry"), closed: &closed},
				}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if response.StatusCode != http.StatusOK || attempts != 3 || closed.Load() != 2 {
		t.Fatalf("expected successful third attempt and closed retry bodies, status=%d attempts=%d closed=%d", response.StatusCode, attempts, closed.Load())
	}
}

func TestRetryTransportRetriesNetworkErrors(t *testing.T) {
	attempts := 0
	transport := retryTransport{
		maxRetries: 1,
		backoff:    time.Millisecond,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return nil, errors.New("temporary dial failure")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if _, err := transport.RoundTrip(req); err != nil || attempts != 2 {
		t.Fatalf("expected network retry to succeed, attempts=%d err=%v", attempts, err)
	}
}

func TestRetryTransportReplaysExplicitIdempotentPostBody(t *testing.T) {
	attempts := 0
	bodies := make([]string, 0, 2)
	transport := retryTransport{
		maxRetries: 1,
		backoff:    time.Millisecond,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			_ = req.Body.Close()
			bodies = append(bodies, string(body))
			if attempts == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"0"}},
					Body:       http.NoBody,
				}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
	}
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/query", strings.NewReader(`{"query":"catalog"}`))
	req = markRequestIdempotent(req)
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if response.StatusCode != http.StatusOK || attempts != 2 {
		t.Fatalf("expected successful replay, status=%d attempts=%d", response.StatusCode, attempts)
	}
	if len(bodies) != 2 || bodies[0] != `{"query":"catalog"}` || bodies[1] != bodies[0] {
		t.Fatalf("expected identical replayed bodies, got %#v", bodies)
	}
}

func TestRetryTransportRequiresReplayableBodyForIdempotentPost(t *testing.T) {
	attempts := 0
	transport := retryTransport{
		maxRetries: 2,
		backoff:    time.Millisecond,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody}, nil
		}),
	}
	body := io.NopCloser(strings.NewReader(`{"query":"catalog"}`))
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/query", body)
	req = markRequestIdempotent(req)
	response, err := transport.RoundTrip(req)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || attempts != 1 {
		t.Fatalf("expected non-replayable request to run once, status=%d attempts=%d err=%v", response.StatusCode, attempts, err)
	}
}

func TestRetryTransportDoesNotRetryPermanentOrUnsafeRequests(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
	}{
		{name: "authentication", method: http.MethodGet, status: http.StatusUnauthorized},
		{name: "not found", method: http.MethodGet, status: http.StatusNotFound},
		{name: "post", method: http.MethodPost, status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			transport := retryTransport{maxRetries: 2, backoff: time.Millisecond, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts++
				return &http.Response{StatusCode: test.status, Body: http.NoBody}, nil
			})}
			req, _ := http.NewRequest(test.method, "http://example.test", nil)
			response, err := transport.RoundTrip(req)
			if err != nil || response.StatusCode != test.status || attempts != 1 {
				t.Fatalf("expected one attempt, status=%d attempts=%d err=%v", response.StatusCode, attempts, err)
			}
		})
	}
}

func TestRetryTransportBackoffHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	transport := retryTransport{
		maxRetries: 2,
		backoff:    time.Second,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			started <- struct{}{}
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody}, nil
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test", nil)
	result := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(req)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("retry backoff did not stop after context cancellation")
	}
}

type trackingReadCloser struct {
	io.Reader
	closed *atomic.Int32
}

func (r *trackingReadCloser) Close() error {
	r.closed.Add(1)
	return nil
}
