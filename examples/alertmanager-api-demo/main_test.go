package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDemoHandlerRequiresBasicAuthAndServesInventory(t *testing.T) {
	server := httptest.NewServer(demoHandler("reader", "private-password"))
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v2/alerts")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected Basic Auth challenge, got %d", response.StatusCode)
	}

	for _, path := range []string{"/api/v2/alerts", "/api/v2/status", "/api/v2/silences"} {
		request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.SetBasicAuth("reader", "private-password")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected %s to succeed, got %d", path, response.StatusCode)
		}
	}
}
