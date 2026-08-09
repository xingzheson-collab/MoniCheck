package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestTempoConnectorSyncsTagsAndValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte("ready-secret-body"))
		case "/api/search/tags":
			if r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
				t.Fatalf("expected bounded tag catalog query, got %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"tagNames":[" resource.service.name ","","span.name","resource.service.name"]}`))
		case "/api/search/tag/resource.service.name/values":
			if r.URL.Query().Get("limit") != "201" || r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
				t.Fatalf("expected bounded tag value query, got %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"tagValues":[{"type":"string","value":"checkout"},{"type":"string","value":"payments"}]}`))
		case "/api/search/tag/span.name/values":
			_, _ = w.Write([]byte(`{"tagValues":["GET /api/orders"]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync tempo: %v", err)
	}
	assertDetailDiscoveryDiagnostic(t, snapshot, "tempo_tag_values", 2, 0)
	if len(snapshot.Resources) != 8 {
		t.Fatalf("expected 8 resources, got %#v", snapshot.Resources)
	}
	if len(snapshot.Relationships) != 3 {
		t.Fatalf("expected 3 relationships, got %#v", snapshot.Relationships)
	}
	var tagCount, valueCount, serviceCount, runtimeCount int
	foundLegacyCompatibleID := false
	for _, resource := range snapshot.Resources {
		if resource.Source.System != "tempo" || resource.Status != model.ResourceStatusActive {
			t.Fatalf("expected tempo active resource, got %#v", resource)
		}
		switch resource.Type {
		case model.ResourceTypeInstance:
			runtimeCount++
			if resource.Name != "Tempo Runtime" ||
				resource.Metadata[model.MetadataTempoRuntime] != "true" ||
				resource.Metadata[model.MetadataTempoReadinessAvailable] != "true" ||
				resource.Metadata[model.MetadataTempoReady] != "true" {
				t.Fatalf("expected ready Tempo runtime metadata, got %#v", resource)
			}
		case model.ResourceTypeTraceTag:
			tagCount++
			if resource.Metadata[model.MetadataTraceTag] == "" || resource.Metadata[model.MetadataTraceTagValueCount] == "" {
				t.Fatalf("expected trace tag metadata, got %#v", resource)
			}
		case model.ResourceTypeTraceTagValue:
			valueCount++
			if resource.Metadata[model.MetadataTraceTag] == "" ||
				resource.Metadata[model.MetadataValueFingerprint] == "" ||
				resource.Metadata[model.MetadataValueRedacted] != "true" ||
				resource.Metadata[model.MetadataTraceTagValue] != "" ||
				len(resource.Labels) != 0 {
				t.Fatalf("expected privacy-safe trace tag value metadata, got %#v", resource)
			}
			if resource.ID == model.StableID("resource", tempoSystem, string(model.ResourceTypeTraceTagValue), "tag:resource.service.name:value:checkout") {
				foundLegacyCompatibleID = true
			}
		case model.ResourceTypeTraceService:
			serviceCount++
			if resource.Labels[model.MetadataService] != resource.Name ||
				resource.Metadata[model.MetadataTraceService] != resource.Name ||
				resource.Metadata[model.MetadataTraceTag] != "resource.service.name" ||
				resource.Metadata[model.MetadataTraceLookback] != "24h0m0s" {
				t.Fatalf("expected Tempo trace service identity, got %#v", resource)
			}
		default:
			t.Fatalf("unexpected resource type %s", resource.Type)
		}
	}
	if tagCount != 2 || valueCount != 3 || serviceCount != 2 || runtimeCount != 1 {
		t.Fatalf("expected 2 tags, 3 values, 2 services, and 1 runtime, got tags=%d values=%d services=%d runtime=%d", tagCount, valueCount, serviceCount, runtimeCount)
	}
	if !foundLegacyCompatibleID {
		t.Fatal("expected redacted value to preserve its legacy resource ID")
	}
	if strings.Contains(fmt.Sprint(snapshot), "GET /api/orders") ||
		strings.Contains(fmt.Sprint(snapshot), "ready-secret-body") {
		t.Fatal("snapshot leaked Tempo tag value or readiness response body")
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Type != model.RelationshipBelongsTo {
			t.Fatalf("expected belongs-to relationship, got %#v", relationship)
		}
	}
	enriched := EnrichBusinessServices(snapshot, time.Unix(0, 0).UTC())
	assertResourceCount(t, enriched, model.ResourceTypeService, 2)
	for _, serviceName := range []string{"checkout", "payments"} {
		var traceServiceID string
		for _, resource := range enriched.Resources {
			if resource.Type == model.ResourceTypeTraceService && resource.Name == serviceName {
				traceServiceID = resource.ID
				break
			}
		}
		if traceServiceID == "" {
			t.Fatalf("expected trace service %q", serviceName)
		}
		assertServiceRelationship(t, enriched, traceServiceID, serviceName, "label.service")
	}
}

func TestTempoConnectorCountsUniqueNonEmptyTagValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.WriteHeader(http.StatusOK)
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tagNames":["tenant.id"]}`))
		case "/api/search/tag/tenant.id/values":
			_, _ = w.Write([]byte(`{"tagValues":[" acme ","acme","","globex"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync tempo: %v", err)
	}
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeTraceTagValue, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeTraceTag && resource.Metadata[model.MetadataTraceTagValueCount] != "2" {
			t.Fatalf("expected unique normalized value count, got %#v", resource.Metadata)
		}
	}
	if strings.Contains(fmt.Sprint(snapshot), "acme") || strings.Contains(fmt.Sprint(snapshot), "globex") {
		t.Fatalf("snapshot leaked normalized Tempo values: %#v", snapshot.Resources)
	}
}

func TestTempoConnectorContinuesWhenOneTagValueRequestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.WriteHeader(http.StatusOK)
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tagNames":["service.name","span.name"]}`))
		case "/api/search/tag/service.name/values":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/api/search/tag/span.name/values":
			_, _ = w.Write([]byte(`{"tagValues":["GET /api/orders"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("partial tempo sync: %v", err)
	}
	assertDetailDiscoveryDiagnostic(t, snapshot, "tempo_tag_values", 2, 1)
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeTraceTag, 2)
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeTraceTagValue, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeTraceTag && resource.Name == "service.name" && resource.Metadata[model.MetadataValueDiscoveryAvailable] != "false" {
			t.Fatalf("expected failed tag detail metadata, got %#v", resource.Metadata)
		}
	}
}

func TestTempoConnectorRequiresTagCatalog(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatal("expected tag catalog failure to fail sync")
	}
}

func TestTempoConnectorMarksTruncatedTagValues(t *testing.T) {
	values := make([]string, 0, defaultTempoTagValueLimit+1)
	for index := 0; index < defaultTempoTagValueLimit+1; index++ {
		values = append(values, fmt.Sprintf("%q", fmt.Sprintf("tenant-%03d", index)))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.WriteHeader(http.StatusOK)
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tags":["tenant.id"]}`))
		case "/api/search/tag/tenant.id/values":
			_, _ = w.Write([]byte(`{"values":[` + strings.Join(values, ",") + `]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync tempo: %v", err)
	}
	var tag model.Resource
	var valueCount int
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeTraceTag {
			tag = resource
		}
		if resource.Type == model.ResourceTypeTraceTagValue {
			valueCount++
			if resource.Metadata[model.MetadataTruncated] != "true" {
				t.Fatalf("expected truncated metadata on sampled value, got %#v", resource)
			}
		}
	}
	if tag.Metadata[model.MetadataTraceTagValueCount] != "201" || tag.Metadata[model.MetadataTruncated] != "true" {
		t.Fatalf("expected tag value count and truncated metadata, got %#v", tag.Metadata)
	}
	if valueCount != defaultTempoTagValueLimit {
		t.Fatalf("expected sampled value count %d, got %d", defaultTempoTagValueLimit, valueCount)
	}
}

func TestTempoConnectorMarksTruncatedServiceDiscoveryPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.WriteHeader(http.StatusOK)
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tagNames":["service.name"]}`))
		case "/api/search/tag/service.name/values":
			if r.URL.Query().Get("limit") != "3" {
				t.Fatalf("expected sentinel limit 3, got %q", r.URL.Query().Get("limit"))
			}
			_, _ = w.Write([]byte(`{"tagValues":["checkout","payments","inventory"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithGovernanceOptions(server.URL, 6*time.Hour, 2, HTTPOptions{})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync tempo: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected truncated Tempo service catalog to produce a partial snapshot")
	}
	assertPrivacyResourceCount(t, snapshot, model.ResourceTypeTraceService, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeTraceTag {
			continue
		}
		if resource.Metadata[model.MetadataTraceServiceDiscoveryTruncated] != "true" ||
			resource.Metadata[model.MetadataTraceServiceCount] != "2" ||
			resource.Metadata[model.MetadataTraceServiceLimit] != "2" ||
			resource.Metadata[model.MetadataTraceLookback] != "6h0m0s" {
			t.Fatalf("unexpected service discovery boundary metadata: %#v", resource.Metadata)
		}
	}
	if snapshot.Diagnostics[0].Metadata["service_discovery_truncated"] != "true" {
		t.Fatalf("expected truncation diagnostic, got %#v", snapshot.Diagnostics)
	}
}

func TestTempoConnectorModelsExplicitNotReadyRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tagNames":[]}`))
		case "/ready":
			http.Error(w, "secret-tempo-not-ready-detail", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync not-ready Tempo: %v", err)
	}
	if snapshot.Partial || len(snapshot.Resources) != 1 {
		t.Fatalf("explicit readiness response should be evaluable and complete: %#v", snapshot)
	}
	runtime := snapshot.Resources[0]
	if runtime.Type != model.ResourceTypeInstance ||
		runtime.Metadata[model.MetadataTempoRuntime] != "true" ||
		runtime.Metadata[model.MetadataTempoReadinessAvailable] != "true" ||
		runtime.Metadata[model.MetadataTempoReady] != "false" {
		t.Fatalf("unexpected not-ready runtime: %#v", runtime)
	}
	diagnostic := findTempoDiagnostic(t, snapshot.Diagnostics, "tempo_readiness")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["available"] != "true" ||
		diagnostic.Metadata["ready"] != "false" ||
		diagnostic.Metadata["status_code"] != "503" {
		t.Fatalf("unexpected not-ready diagnostic: %#v", diagnostic)
	}
	if strings.Contains(fmt.Sprint(snapshot), "secret-tempo-not-ready-detail") {
		t.Fatalf("readiness response body leaked: %#v", snapshot)
	}
}

func TestTempoConnectorKeepsUnavailableReadinessUnevaluable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/search/tags":
			_, _ = w.Write([]byte(`{"tagNames":[]}`))
		case "/ready":
			http.Error(w, "secret-tempo-missing-detail", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewTempoConnectorWithOptions(server.URL, HTTPOptions{MaxRetries: -1})
	if err != nil {
		t.Fatalf("new tempo connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync Tempo with unavailable readiness: %v", err)
	}
	if !snapshot.Partial || len(snapshot.Resources) != 0 {
		t.Fatalf("unavailable readiness should be partial and create no runtime: %#v", snapshot)
	}
	diagnostic := findTempoDiagnostic(t, snapshot.Diagnostics, "tempo_readiness")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["available"] != "false" ||
		diagnostic.Metadata["status_code"] != "404" ||
		diagnostic.Metadata["ready"] != "" {
		t.Fatalf("unavailable readiness must remain unevaluable: %#v", diagnostic)
	}
	if strings.Contains(fmt.Sprint(snapshot), "secret-tempo-missing-detail") {
		t.Fatalf("unavailable readiness body leaked: %#v", snapshot)
	}
}

func findTempoDiagnostic(t *testing.T, diagnostics []model.Diagnostic, id string) model.Diagnostic {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.ID == id {
			return diagnostic
		}
	}
	t.Fatalf("missing Tempo diagnostic %q: %#v", id, diagnostics)
	return model.Diagnostic{}
}
