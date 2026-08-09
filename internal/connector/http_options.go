package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConnectorMaxRetries = 2
	defaultConnectorBackoff    = 100 * time.Millisecond
	maxConnectorRetryDelay     = 2 * time.Second
)

type HTTPOptions struct {
	BearerToken        string
	Username           string
	Password           string
	APIKey             string
	Headers            map[string]string
	InsecureSkipVerify bool
	CAFile             string
	ClientCertFile     string
	ClientKeyFile      string
	Timeout            time.Duration
	MaxRetries         int
	RetryBackoff       time.Duration
}

func NewHTTPClient(options HTTPOptions) (*http.Client, error) {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	clientCertFile := strings.TrimSpace(options.ClientCertFile)
	clientKeyFile := strings.TrimSpace(options.ClientKeyFile)
	if (clientCertFile == "") != (clientKeyFile == "") {
		return nil, errors.New("TLS client certificate and key files must be configured together")
	}
	if options.InsecureSkipVerify || strings.TrimSpace(options.CAFile) != "" || clientCertFile != "" {
		tlsConfig := &tls.Config{InsecureSkipVerify: options.InsecureSkipVerify} //nolint:gosec // Explicit connector option for self-hosted deployments.
		if strings.TrimSpace(options.CAFile) != "" {
			pool, err := loadCertPool(options.CAFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS CA file: %w", err)
			}
			tlsConfig.RootCAs = pool
		}
		if clientCertFile != "" {
			certificate, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		transport.TLSClientConfig = tlsConfig
	}
	maxRetries := options.MaxRetries
	if maxRetries == 0 {
		maxRetries = defaultConnectorMaxRetries
	} else if maxRetries < 0 {
		maxRetries = 0
	}
	retryBackoff := options.RetryBackoff
	if retryBackoff <= 0 {
		retryBackoff = defaultConnectorBackoff
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: authTransport{base: retryTransport{base: transport, maxRetries: maxRetries, backoff: retryBackoff}, options: options},
	}, nil
}

type authTransport struct {
	base    http.RoundTripper
	options HTTPOptions
}

func (t authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if token := strings.TrimSpace(t.options.BearerToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if username := strings.TrimSpace(t.options.Username); username != "" {
		req.SetBasicAuth(username, t.options.Password)
	}
	if apiKey := strings.TrimSpace(t.options.APIKey); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	for key, value := range t.options.Headers {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	return t.base.RoundTrip(req)
}

type retryTransport struct {
	base       http.RoundTripper
	maxRetries int
	backoff    time.Duration
}

type idempotentRetryContextKey struct{}

func markRequestIdempotent(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	return req.WithContext(context.WithValue(req.Context(), idempotentRetryContextKey{}, true))
}

func (t retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !retryableRequest(req) || t.maxRetries <= 0 {
		return t.base.RoundTrip(req)
	}
	for attempt := 0; ; attempt++ {
		attemptRequest, err := retryAttemptRequest(req, attempt)
		if err != nil {
			return nil, err
		}
		response, err := t.base.RoundTrip(attemptRequest)
		if !retryableResult(req, response, err) || attempt >= t.maxRetries {
			return response, err
		}
		if response != nil && response.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
		}
		if err := waitForRetry(req, connectorRetryDelay(response, attempt, t.backoff)); err != nil {
			return nil, err
		}
	}
}

func retryableRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return req.Body == nil || req.Body == http.NoBody
	}
	idempotent, _ := req.Context().Value(idempotentRetryContextKey{}).(bool)
	if !idempotent {
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func retryAttemptRequest(req *http.Request, attempt int) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if attempt == 0 || req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("replay idempotent request body: %w", err)
	}
	clone.Body = body
	return clone, nil
}

func retryableResult(req *http.Request, response *http.Response, err error) bool {
	if req.Context().Err() != nil {
		return false
	}
	if err != nil {
		return true
	}
	if response == nil {
		return false
	}
	return response.StatusCode == http.StatusRequestTimeout ||
		response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode >= http.StatusInternalServerError
}

func connectorRetryDelay(response *http.Response, attempt int, base time.Duration) time.Duration {
	if response != nil {
		if delay, ok := parseRetryAfter(response.Header.Get("Retry-After")); ok {
			return min(delay, maxConnectorRetryDelay)
		}
	}
	delay := base * time.Duration(1<<attempt)
	return min(delay, maxConnectorRetryDelay)
}

func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(0, time.Until(when)), true
}

func waitForRetry(req *http.Request, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		return req.Context().Err()
	case <-timer.C:
		return nil
	}
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA file %s", path)
	}
	return pool, nil
}
