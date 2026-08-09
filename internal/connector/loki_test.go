package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monicheck/internal/model"
)

func TestLokiConnectorSyncsLabelsAndValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scope-OrgID") != "tenant-a" {
			t.Fatalf("missing Loki tenant header for %s: %q", r.URL.Path, r.Header.Get("X-Scope-OrgID"))
		}
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":[" app ","","namespace","app"]}`))
		case "/loki/api/v1/label/app/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["checkout","payments"]}`))
		case "/loki/api/v1/label/namespace/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["prod"]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{Headers: map[string]string{"X-Scope-OrgID": "tenant-a"}})
	if err != nil {
		t.Fatalf("new loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync loki: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected complete Loki snapshot: %#v", snapshot.Diagnostics)
	}
	assertLokiDetailDiscoveryDiagnostic(t, snapshot, 2, 0)
	assertLokiReadinessDiagnostic(t, snapshot, true, true, http.StatusOK)
	if len(snapshot.Resources) != 6 {
		t.Fatalf("expected 6 resources, got %#v", snapshot.Resources)
	}
	if len(snapshot.Relationships) != 3 {
		t.Fatalf("expected 3 relationships, got %#v", snapshot.Relationships)
	}
	var labelCount, valueCount, runtimeCount int
	foundLegacyCompatibleID := false
	for _, resource := range snapshot.Resources {
		if resource.Source.System != "loki" || resource.Status != model.ResourceStatusActive {
			t.Fatalf("expected loki active resource, got %#v", resource)
		}
		switch resource.Type {
		case model.ResourceTypeInstance:
			runtimeCount++
			if resource.Name != "Loki Runtime" ||
				resource.Source.ExternalID != "runtime" ||
				resource.Metadata[model.MetadataLokiRuntime] != "true" ||
				resource.Metadata[model.MetadataLokiReadinessAvailable] != "true" ||
				resource.Metadata[model.MetadataLokiReady] != "true" {
				t.Fatalf("unexpected Loki runtime resource: %#v", resource)
			}
		case model.ResourceTypeLogLabel:
			labelCount++
			if resource.Metadata[model.MetadataLogLabel] == "" || resource.Metadata[model.MetadataLogLabelValueCount] == "" {
				t.Fatalf("expected label metadata, got %#v", resource)
			}
		case model.ResourceTypeLogLabelValue:
			valueCount++
			if resource.Metadata[model.MetadataLogLabel] == "" ||
				resource.Metadata[model.MetadataValueFingerprint] == "" ||
				resource.Metadata[model.MetadataValueRedacted] != "true" ||
				resource.Metadata[model.MetadataLogLabelValue] != "" ||
				len(resource.Labels) != 0 {
				t.Fatalf("expected privacy-safe label value metadata, got %#v", resource)
			}
			if resource.ID == model.StableID("resource", lokiSystem, string(model.ResourceTypeLogLabelValue), "label:app:value:checkout") {
				foundLegacyCompatibleID = true
			}
		default:
			t.Fatalf("unexpected resource type %s", resource.Type)
		}
	}
	if labelCount != 2 || valueCount != 3 || runtimeCount != 1 {
		t.Fatalf("expected 2 labels, 3 values, and 1 runtime, got labels=%d values=%d runtime=%d", labelCount, valueCount, runtimeCount)
	}
	if !foundLegacyCompatibleID {
		t.Fatal("expected redacted value to preserve its legacy resource ID")
	}
	for _, rawValue := range []string{"checkout", "payments", "prod"} {
		if strings.Contains(fmt.Sprint(snapshot), rawValue) {
			t.Fatalf("snapshot leaked raw Loki label value %q", rawValue)
		}
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Type != model.RelationshipBelongsTo {
			t.Fatalf("expected belongs-to relationship, got %#v", relationship)
		}
	}
}

func TestLokiConnectorCountsUniqueNonEmptyLabelValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":["tenant"]}`))
		case "/loki/api/v1/label/tenant/values":
			_, _ = w.Write([]byte(`{"status":"success","data":[" acme ","acme","","globex"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync loki: %v", err)
	}
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeLogLabelValue, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeLogLabel && resource.Metadata[model.MetadataLogLabelValueCount] != "2" {
			t.Fatalf("expected unique normalized value count, got %#v", resource.Metadata)
		}
	}
	if strings.Contains(fmt.Sprint(snapshot), "acme") || strings.Contains(fmt.Sprint(snapshot), "globex") {
		t.Fatalf("snapshot leaked normalized Loki values: %#v", snapshot.Resources)
	}
}

func TestLokiConnectorContinuesWhenOneLabelValueRequestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":["app","namespace"]}`))
		case "/loki/api/v1/label/app/values":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/loki/api/v1/label/namespace/values":
			_, _ = w.Write([]byte(`{"status":"success","data":["prod"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("partial loki sync: %v", err)
	}
	assertLokiDetailDiscoveryDiagnostic(t, snapshot, 2, 1)
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeLogLabel, 2)
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeLogLabelValue, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeLogLabel && resource.Name == "app" && resource.Metadata[model.MetadataValueDiscoveryAvailable] != "false" {
			t.Fatalf("expected failed label detail metadata, got %#v", resource.Metadata)
		}
	}
}

func TestLokiConnectorRequiresLabelCatalog(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new loki connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected label catalog failure to fail sync")
	}
}

func TestLokiConnectorMarksTruncatedLabelValues(t *testing.T) {
	values := make([]string, 0, lokiMaxLabelValues+1)
	for index := 0; index < lokiMaxLabelValues+1; index++ {
		values = append(values, fmt.Sprintf("%q", fmt.Sprintf("user-%03d", index)))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":["user_id"]}`))
		case "/loki/api/v1/label/user_id/values":
			_, _ = w.Write([]byte(`{"status":"success","data":[` + strings.Join(values, ",") + `]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync loki: %v", err)
	}
	var label model.Resource
	var valueCount int
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeLogLabel {
			label = resource
		}
		if resource.Type == model.ResourceTypeLogLabelValue {
			valueCount++
			if resource.Metadata[model.MetadataTruncated] != "true" {
				t.Fatalf("expected truncated metadata on sampled value, got %#v", resource)
			}
		}
	}
	if label.Metadata[model.MetadataLogLabelValueCount] != "201" || label.Metadata[model.MetadataTruncated] != "true" {
		t.Fatalf("expected label value count and truncated metadata, got %#v", label.Metadata)
	}
	if valueCount != lokiMaxLabelValues {
		t.Fatalf("expected sampled value count %d, got %d", lokiMaxLabelValues, valueCount)
	}
}

func TestLokiConnectorReportsExplicitNotReady(t *testing.T) {
	const secret = "LOKI_SECRET_NOT_READY_3ca9"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			http.Error(w, secret, http.StatusServiceUnavailable)
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new Loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync Loki: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("explicit not-ready response remains evaluable: %#v", snapshot.Diagnostics)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	assertLokiReadinessDiagnostic(t, snapshot, true, false, http.StatusServiceUnavailable)
	if strings.Contains(fmt.Sprint(snapshot), secret) {
		t.Fatalf("snapshot leaked readiness response body: %#v", snapshot)
	}
}

func TestLokiConnectorTreatsUnavailableReadinessAsUnevaluable(t *testing.T) {
	const secret = "LOKI_SECRET_MISSING_READY_5b71"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			http.Error(w, secret, http.StatusNotFound)
		case "/loki/api/v1/labels":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewLokiConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new Loki connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync Loki: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("unavailable readiness should make snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 0)
	assertLokiReadinessDiagnostic(t, snapshot, false, false, http.StatusNotFound)
	if strings.Contains(fmt.Sprint(snapshot), secret) {
		t.Fatalf("snapshot leaked readiness response body: %#v", snapshot)
	}
}

func assertLokiReadinessDiagnostic(t *testing.T, snapshot Snapshot, available, ready bool, statusCode int) {
	t.Helper()
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID != "loki_readiness" {
			continue
		}
		if diagnostic.Metadata["available"] != fmt.Sprintf("%t", available) ||
			diagnostic.Metadata["status_code"] != fmt.Sprintf("%d", statusCode) ||
			diagnostic.Metadata["scope"] != "configured_component" {
			t.Fatalf("unexpected Loki readiness diagnostic: %#v", diagnostic)
		}
		if available && diagnostic.Metadata["ready"] != fmt.Sprintf("%t", ready) {
			t.Fatalf("unexpected Loki readiness state: %#v", diagnostic)
		}
		if !available && diagnostic.Metadata["ready"] != "" {
			t.Fatalf("unavailable readiness must remain unevaluable: %#v", diagnostic)
		}
		return
	}
	t.Fatalf("missing Loki readiness diagnostic: %#v", snapshot.Diagnostics)
}

func assertLokiDetailDiscoveryDiagnostic(t *testing.T, snapshot Snapshot, total, failed int) {
	t.Helper()
	if snapshot.Partial != (failed > 0) {
		t.Fatalf("unexpected partial state %t for failed count %d", snapshot.Partial, failed)
	}
	for _, diagnostic := range snapshot.Diagnostics {
		if diagnostic.ID != "loki_label_values" {
			continue
		}
		expectedStatus := model.ExecutionStatusSucceeded
		if failed > 0 {
			expectedStatus = model.ExecutionStatusWarning
		}
		expectedWorkers := total
		if expectedWorkers > defaultConnectorDetailWorkers {
			expectedWorkers = defaultConnectorDetailWorkers
		}
		if diagnostic.Status != expectedStatus ||
			diagnostic.Metadata["item_count"] != fmt.Sprintf("%d", total) ||
			diagnostic.Metadata["failed_count"] != fmt.Sprintf("%d", failed) ||
			diagnostic.Metadata["worker_count"] != fmt.Sprintf("%d", expectedWorkers) {
			t.Fatalf("unexpected Loki detail diagnostic: %#v", diagnostic)
		}
		return
	}
	t.Fatalf("missing Loki label detail diagnostic: %#v", snapshot.Diagnostics)
}
