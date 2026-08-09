package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestPyroscopeConnectorDiscoversProfilesLabelsAndServices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Scope-OrgID") != "tenant-a" {
			t.Fatalf("unexpected request method or headers: method=%s headers=%v", r.Method, r.Header)
		}
		if r.URL.Path == "/ready" {
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected readiness method %s", r.Method)
			}
			_, _ = w.Write([]byte("ready"))
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected catalog method %s", r.Method)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["start"] == nil || body["end"] == nil {
			t.Fatalf("expected bounded query window, got %#v", body)
		}
		switch r.URL.Path {
		case "/querier.v1.QuerierService/LabelNames":
			_, _ = w.Write([]byte(`{"names":[" service_name ","service.name","request_id","environment","service_name",""]}`))
		case "/querier.v1.QuerierService/ProfileTypes":
			_, _ = w.Write([]byte(`{"profileTypes":[{"ID":"process_cpu:cpu:nanoseconds:cpu:nanoseconds","name":"process_cpu","sampleType":"cpu","sampleUnit":"nanoseconds","periodType":"cpu","periodUnit":"nanoseconds"},{"ID":"process_cpu:cpu:nanoseconds:cpu:nanoseconds","name":"process_cpu","sampleType":"cpu","sampleUnit":"nanoseconds","periodType":"cpu","periodUnit":"nanoseconds"}]}`))
		case "/querier.v1.QuerierService/LabelValues":
			switch body["name"] {
			case "service_name", "service.name":
				_, _ = w.Write([]byte(`{"names":["checkout","payments"]}`))
			case "request_id":
				_, _ = w.Write([]byte(`{"names":["req-1","req-2","req-3"]}`))
			case "environment":
				_, _ = w.Write([]byte(`{"names":["prod","staging"]}`))
			default:
				t.Fatalf("unexpected label %v", body["name"])
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewPyroscopeConnectorWithOptions(server.URL, 6*time.Hour, HTTPOptions{
		BearerToken: "secret",
		Headers:     map[string]string{"X-Scope-OrgID": "tenant-a"},
	})
	if err != nil {
		t.Fatalf("new pyroscope connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync pyroscope: %v", err)
	}
	assertPyroscopeDetailDiscoveryDiagnostic(t, snapshot, 4, 0)
	if snapshot.Partial || len(snapshot.Resources) != 17 || len(snapshot.Relationships) != 9 {
		t.Fatalf("unexpected pyroscope snapshot: resources=%d relationships=%d partial=%v", len(snapshot.Resources), len(snapshot.Relationships), snapshot.Partial)
	}

	counts := make(map[model.ResourceType]int)
	var profileType model.Resource
	var runtime model.Resource
	serviceNames := make(map[string]bool)
	for _, resource := range snapshot.Resources {
		counts[resource.Type]++
		if resource.Source.System != pyroscopeSystem || resource.Status != model.ResourceStatusActive {
			t.Fatalf("unexpected source/status: %#v", resource)
		}
		switch resource.Type {
		case model.ResourceTypeInstance:
			runtime = resource
		case model.ResourceTypeProfileType:
			profileType = resource
		case model.ResourceTypeProfileService:
			serviceNames[resource.Name] = true
			if resource.Metadata[model.MetadataService] == "" {
				t.Fatalf("profile service should carry service identity: %#v", resource)
			}
		case model.ResourceTypeProfileLabelValue:
			if resource.Metadata[model.MetadataValueFingerprint] == "" || resource.Metadata[model.MetadataValueRedacted] != "true" {
				t.Fatalf("profile label value should be redacted: %#v", resource)
			}
		}
	}
	if counts[model.ResourceTypeProfileType] != 1 || counts[model.ResourceTypeProfileLabel] != 4 ||
		counts[model.ResourceTypeProfileLabelValue] != 9 || counts[model.ResourceTypeProfileService] != 2 ||
		counts[model.ResourceTypeInstance] != 1 {
		t.Fatalf("unexpected resource type counts: %#v", counts)
	}
	if runtime.Name != "Pyroscope Runtime" ||
		runtime.Metadata[model.MetadataPyroscopeRuntime] != "true" ||
		runtime.Metadata[model.MetadataPyroscopeReadinessAvailable] != "true" ||
		runtime.Metadata[model.MetadataPyroscopeReady] != "true" {
		t.Fatalf("unexpected Pyroscope runtime resource: %#v", runtime)
	}
	readinessDiagnostic := findPyroscopeDiagnostic(t, snapshot.Diagnostics, "pyroscope_readiness")
	if readinessDiagnostic.Status != model.ExecutionStatusSucceeded ||
		readinessDiagnostic.Metadata["ready"] != "true" {
		t.Fatalf("unexpected readiness diagnostic: %#v", readinessDiagnostic)
	}
	if profileType.Metadata[model.MetadataProfileSampleType] != "cpu" || profileType.Metadata[model.MetadataProfileSampleUnit] != "nanoseconds" {
		t.Fatalf("unexpected profile type metadata: %#v", profileType.Metadata)
	}
	if !serviceNames["checkout"] || !serviceNames["payments"] {
		t.Fatalf("expected profile services, got %#v", serviceNames)
	}
	for _, secretValue := range []string{"req-1", "req-2", "req-3", "prod", "staging"} {
		if strings.Contains(fmt.Sprint(snapshot), secretValue) {
			t.Fatalf("snapshot leaked raw label value %q", secretValue)
		}
	}
}

func TestPyroscopeConnectorKeepsCatalogWhenOneLabelValueRequestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/querier.v1.QuerierService/LabelNames":
			_, _ = w.Write([]byte(`{"names":["service_name","request_id"]}`))
		case "/querier.v1.QuerierService/ProfileTypes":
			_, _ = w.Write([]byte(`{"profileTypes":[]}`))
		case "/querier.v1.QuerierService/LabelValues":
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Name == "request_id" {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"names":["checkout"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewPyroscopeConnectorWithOptions(server.URL, time.Hour, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("partial sync should succeed: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected partial snapshot")
	}
	assertPyroscopeDetailDiscoveryDiagnostic(t, snapshot, 2, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeProfileLabel && resource.Name == "request_id" &&
			resource.Metadata[model.MetadataValueDiscoveryAvailable] != "false" {
			t.Fatalf("expected unavailable value discovery metadata: %#v", resource)
		}
	}
}

func TestPyroscopeConnectorRequiresCoreCatalogs(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	connector, err := NewPyroscopeConnectorWithOptions(server.URL, time.Hour, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected core catalog failure")
	}
}

func TestPyroscopeConnectorRetriesReadOnlyConnectQueries(t *testing.T) {
	labelNameAttempts := 0
	labelNameBodies := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/querier.v1.QuerierService/LabelNames":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read label names body: %v", err)
			}
			labelNameAttempts++
			labelNameBodies = append(labelNameBodies, string(body))
			if labelNameAttempts == 1 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"names":[]}`))
		case "/querier.v1.QuerierService/ProfileTypes":
			_, _ = w.Write([]byte(`{"profileTypes":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewPyroscopeConnectorWithOptions(server.URL, time.Hour, HTTPOptions{
		MaxRetries:   1,
		RetryBackoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync after transient failure: %v", err)
	}
	if snapshot.Partial || labelNameAttempts != 2 {
		t.Fatalf("expected complete sync after one retry, partial=%v attempts=%d", snapshot.Partial, labelNameAttempts)
	}
	if len(labelNameBodies) != 2 || labelNameBodies[0] == "" || labelNameBodies[1] != labelNameBodies[0] {
		t.Fatalf("expected identical Connect request replay, got %#v", labelNameBodies)
	}
}

func TestPyroscopeConnectorMapsExplicitNotReadyWithoutPersistingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			http.Error(w, "secret-readiness-detail", http.StatusServiceUnavailable)
		case "/querier.v1.QuerierService/LabelNames":
			_, _ = w.Write([]byte(`{"names":[]}`))
		case "/querier.v1.QuerierService/ProfileTypes":
			_, _ = w.Write([]byte(`{"profileTypes":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewPyroscopeConnectorWithOptions(server.URL, time.Hour, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync not-ready runtime: %v", err)
	}
	if snapshot.Partial || len(snapshot.Resources) != 1 {
		t.Fatalf("explicit readiness response should be evaluable and complete: %#v", snapshot)
	}
	runtime := snapshot.Resources[0]
	if runtime.Type != model.ResourceTypeInstance ||
		runtime.Metadata[model.MetadataPyroscopeReady] != "false" {
		t.Fatalf("unexpected not-ready runtime: %#v", runtime)
	}
	diagnostic := findPyroscopeDiagnostic(t, snapshot.Diagnostics, "pyroscope_readiness")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["status_code"] != "503" ||
		diagnostic.Metadata["ready"] != "false" {
		t.Fatalf("unexpected not-ready diagnostic: %#v", diagnostic)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(encoded), "secret-readiness-detail") {
		t.Fatalf("readiness response body leaked: %s", encoded)
	}
}

func TestPyroscopeConnectorTreatsUnavailableReadinessAsPartialAndUnevaluable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			http.Error(w, "secret-proxy-body", http.StatusNotFound)
		case "/querier.v1.QuerierService/LabelNames":
			_, _ = w.Write([]byte(`{"names":[]}`))
		case "/querier.v1.QuerierService/ProfileTypes":
			_, _ = w.Write([]byte(`{"profileTypes":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewPyroscopeConnectorWithOptions(server.URL, time.Hour, HTTPOptions{})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync unavailable readiness: %v", err)
	}
	if !snapshot.Partial || len(snapshot.Resources) != 0 {
		t.Fatalf("unavailable readiness should be partial and create no runtime: %#v", snapshot)
	}
	diagnostic := findPyroscopeDiagnostic(t, snapshot.Diagnostics, "pyroscope_readiness")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["available"] != "false" ||
		diagnostic.Metadata["status_code"] != "404" {
		t.Fatalf("unexpected unavailable diagnostic: %#v", diagnostic)
	}
	if strings.Contains(fmt.Sprint(snapshot), "secret-proxy-body") {
		t.Fatalf("unavailable readiness body leaked: %#v", snapshot)
	}
}

func findPyroscopeDiagnostic(t *testing.T, diagnostics []model.Diagnostic, id string) model.Diagnostic {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.ID == id {
			return diagnostic
		}
	}
	t.Fatalf("diagnostic %q not found: %#v", id, diagnostics)
	return model.Diagnostic{}
}

func assertPyroscopeDetailDiscoveryDiagnostic(t *testing.T, snapshot Snapshot, total, failed int) {
	t.Helper()
	diagnostic := findPyroscopeDiagnostic(t, snapshot.Diagnostics, "pyroscope_label_values")
	expectedStatus := model.ExecutionStatusSucceeded
	if failed > 0 {
		expectedStatus = model.ExecutionStatusWarning
	}
	if diagnostic.Status != expectedStatus ||
		diagnostic.Metadata["item_count"] != fmt.Sprintf("%d", total) ||
		diagnostic.Metadata["failed_count"] != fmt.Sprintf("%d", failed) {
		t.Fatalf("unexpected Pyroscope detail diagnostic: %#v", diagnostic)
	}
	expectedWorkers := total
	if expectedWorkers > defaultConnectorDetailWorkers {
		expectedWorkers = defaultConnectorDetailWorkers
	}
	if diagnostic.Metadata["worker_count"] != fmt.Sprintf("%d", expectedWorkers) {
		t.Fatalf("expected worker_count=%d, got %#v", expectedWorkers, diagnostic.Metadata)
	}
}
