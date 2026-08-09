package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrometheusAPIDemoProvidesFreshBoundedInventory(t *testing.T) {
	for _, path := range []string{
		"/api/v1/label/__name__/values", "/api/v1/metadata", "/api/v1/targets",
		"/api/v1/rules", "/api/v1/status/tsdb", "/api/v1/status/flags",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		prometheusAPI(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, response.Code)
		}
		var envelope struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Status != "success" {
			t.Fatalf("%s returned invalid Prometheus envelope: status=%q err=%v", path, envelope.Status, err)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	response := httptest.NewRecorder()
	prometheusAPI(response, request)
	var targets struct {
		Data struct {
			ActiveTargets []struct {
				LastScrape time.Time `json:"lastScrape"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &targets); err != nil || len(targets.Data.ActiveTargets) != 1 {
		t.Fatalf("decode targets: targets=%#v err=%v", targets, err)
	}
	if age := time.Since(targets.Data.ActiveTargets[0].LastScrape); age < 0 || age > time.Minute {
		t.Fatalf("demo target scrape is not fresh: %s", age)
	}
}

func TestPrometheusAPIDemoRejectsUnknownPaths(t *testing.T) {
	response := httptest.NewRecorder()
	prometheusAPI(response, httptest.NewRequest(http.MethodGet, "/api/v1/admin/tsdb/delete_series", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown path returned %d", response.Code)
	}
}

func TestPrometheusAPIDemoCanExerciseJobBasedServiceInference(t *testing.T) {
	response := httptest.NewRecorder()
	servePrometheusAPI(response, httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil), false)
	if response.Code != http.StatusOK {
		t.Fatalf("targets returned %d", response.Code)
	}
	var targets struct {
		Data struct {
			ActiveTargets []struct {
				Labels map[string]string `json:"labels"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &targets); err != nil || len(targets.Data.ActiveTargets) != 1 {
		t.Fatalf("decode targets: targets=%#v err=%v", targets, err)
	}
	labels := targets.Data.ActiveTargets[0].Labels
	if labels["job"] != "checkout" || labels["service"] != "" {
		t.Fatalf("expected job-only service identity fixture, got %#v", labels)
	}
}

func TestPrometheusAPIDemoRequiresLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:19090", "[::1]:19090", "localhost:19090"} {
		if err := validateAddress(address); err != nil {
			t.Fatalf("loopback %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:19090", "192.0.2.1:19090", "not-an-address"} {
		if err := validateAddress(address); err == nil {
			t.Fatalf("non-loopback %q accepted", address)
		}
	}
}

func TestPrometheusAPIDemoBasicAuthFixture(t *testing.T) {
	handler := basicAuthHandler(http.HandlerFunc(prometheusAPI), "reader", "private-password")
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("expected Basic Auth challenge, got status=%d headers=%v", unauthorized.Code, unauthorized.Header())
	}
	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/targets", nil)
	authorizedRequest.SetBasicAuth("reader", "private-password")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("expected authenticated fixture response, got %d", authorized.Code)
	}
}
