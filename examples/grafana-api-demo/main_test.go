package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthHandler(t *testing.T) {
	handler := basicAuthHandler(http.HandlerFunc(grafanaAPI), "reader", "private-password")
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("expected Basic Auth challenge, got %d", unauthorized.Code)
	}
	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	authorizedRequest.SetBasicAuth("reader", "private-password")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("expected authorized response, got %d", authorized.Code)
	}
}

func TestGrafanaAPIProvidesActivationInventory(t *testing.T) {
	for _, path := range []string{"/api/datasources", "/api/search?type=dash-db", "/api/dashboards/uid/checkout", "/api/health"} {
		response := httptest.NewRecorder()
		grafanaAPI(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("expected fixture response for %s, got %d", path, response.Code)
		}
	}
}
