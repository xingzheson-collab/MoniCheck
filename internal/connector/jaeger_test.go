package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestJaegerConnectorSync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/services":
			fmt.Fprint(w, `{"data":[" checkout ","","payments","checkout"]}`)
		case r.URL.Path == "/api/operations" && r.URL.Query().Get("service") == "checkout":
			fmt.Fprint(w, `{"data":[{"name":"GET /checkout","spanKind":"server"},"publish-order"]}`)
		case r.URL.Path == "/api/operations" && r.URL.Query().Get("service") == "payments":
			fmt.Fprint(w, `{"data":[{"name":"POST /charge","spanKind":"client"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync jaeger: %v", err)
	}
	assertDetailDiscoveryDiagnostic(t, snapshot, "jaeger_operations", 2, 0)
	assertResourceCount(t, snapshot, model.ResourceTypeService, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 3)
	assertRelationship(t, snapshot, model.RelationshipBelongsTo, model.ResourceTypeTraceOperation, model.ResourceTypeService)

	var checkoutOperation model.Resource
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeTraceOperation && resource.Metadata[model.MetadataTraceOperation] == "GET /checkout" {
			checkoutOperation = resource
			break
		}
	}
	if checkoutOperation.ID == "" || checkoutOperation.Metadata[model.MetadataTraceService] != "checkout" || checkoutOperation.Metadata[model.MetadataTraceOperationKind] != "server" {
		t.Fatalf("expected checkout operation metadata, got %#v", checkoutOperation)
	}
}

func TestJaegerConnectorContinuesWhenOneOperationRequestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/services":
			fmt.Fprint(w, `{"data":["checkout","payments"]}`)
		case r.URL.Path == "/api/operations" && r.URL.Query().Get("service") == "checkout":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case r.URL.Path == "/api/operations" && r.URL.Query().Get("service") == "payments":
			fmt.Fprint(w, `{"data":["POST /charge"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("partial jaeger sync: %v", err)
	}
	assertDetailDiscoveryDiagnostic(t, snapshot, "jaeger_operations", 2, 1)
	assertResourceCount(t, snapshot, model.ResourceTypeService, 2)
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == "checkout" && resource.Metadata[model.MetadataOperationDiscoveryAvailable] != "false" {
			t.Fatalf("expected failed operation detail metadata, got %#v", resource.Metadata)
		}
	}
}

func TestJaegerConnectorRejectsErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[],"errors":[{"msg":"boom"}]}`)
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	if _, err := connector.Sync(context.Background()); err == nil {
		t.Fatalf("expected jaeger sync error")
	}
}

func TestJaegerConnectorDeduplicatesAndMergesOperationKinds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":["checkout"]}`)
		case "/api/operations":
			fmt.Fprint(w, `{"data":[{"name":"GET /checkout","spanKind":"server"},{"name":" GET /checkout ","spanKind":"client"},{"name":"GET /checkout","spanKind":"server"},"publish-order",""]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithOptions(server.URL, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync jaeger: %v", err)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 2)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Metadata[model.MetadataOperationCount] != "2" {
			t.Fatalf("expected unique operation count, got %#v", resource.Metadata)
		}
		if resource.Type == model.ResourceTypeTraceOperation && resource.Metadata[model.MetadataTraceOperation] == "GET /checkout" {
			if resource.Metadata[model.MetadataTraceOperationKind] != "" ||
				resource.Metadata[model.MetadataTraceOperationKinds] != "client,server" ||
				resource.Metadata[model.MetadataTraceOperationKindCount] != "2" {
				t.Fatalf("expected merged operation kinds, got %#v", resource.Metadata)
			}
		}
	}
}

func TestJaegerConnectorMarksOperationLimitAsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":["checkout"]}`)
		case "/api/operations":
			fmt.Fprint(w, `{"data":["z-last","a-first","m-middle","a-first"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithGovernanceOptions(server.URL, 2, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync jaeger: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected truncated operation discovery to mark snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 2)
	var operationNames []string
	for _, resource := range snapshot.Resources {
		switch resource.Type {
		case model.ResourceTypeService:
			if resource.Metadata[model.MetadataOperationCount] != "3" ||
				resource.Metadata[model.MetadataOperationLimit] != "2" ||
				resource.Metadata[model.MetadataOperationDiscoveryTruncated] != "true" {
				t.Fatalf("unexpected operation limit metadata: %#v", resource.Metadata)
			}
		case model.ResourceTypeTraceOperation:
			operationNames = append(operationNames, resource.Metadata[model.MetadataTraceOperation])
		}
	}
	if fmt.Sprint(operationNames) != "[a-first m-middle]" {
		t.Fatalf("expected deterministic sorted operation sample, got %#v", operationNames)
	}
	if snapshot.Diagnostics[0].Status != model.ExecutionStatusWarning ||
		snapshot.Diagnostics[0].Metadata["operation_limit"] != "2" ||
		snapshot.Diagnostics[0].Metadata["truncated_service_count"] != "1" {
		t.Fatalf("unexpected truncation diagnostic: %#v", snapshot.Diagnostics)
	}
}

func TestJaegerConnectorRejectsExcessiveOperationLimit(t *testing.T) {
	if _, err := NewJaegerConnectorWithGovernanceOptions("http://jaeger:16686", maxJaegerOperationLimit+1, HTTPOptions{}); err == nil {
		t.Fatal("expected excessive operation limit to fail")
	}
}

func TestJaegerConnectorMapsV2UnhealthyRuntimeWithoutRetainingBody(t *testing.T) {
	var healthAuthorization string
	query := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":[]}`)
		case "/api/dependencies":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer query.Close()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthAuthorization = r.Header.Get("Authorization")
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"healthy":false,"status":"error","attributes":{"error_msg":"secret storage detail"}}`)
	}))
	defer health.Close()

	connector, err := NewJaegerConnectorWithRuntimeOptions(query.URL, health.URL+"/status", 1000, time.Hour, 100, HTTPOptions{BearerToken: "query-secret"})
	if err != nil {
		t.Fatalf("new Jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync Jaeger: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected evaluable health response to remain complete: %#v", snapshot.Diagnostics)
	}
	if healthAuthorization != "" {
		t.Fatalf("query credentials must not be forwarded to Jaeger health URL, got %q", healthAuthorization)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeInstance, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeInstance {
			continue
		}
		if resource.Metadata[model.MetadataJaegerHealthy] != "false" ||
			resource.Metadata[model.MetadataJaegerHealthSource] != "healthcheckv2" ||
			strings.Contains(fmt.Sprint(resource), "secret storage detail") {
			t.Fatalf("unexpected Jaeger runtime: %#v", resource)
		}
	}
	diagnostic := diagnosticByID(snapshot.Diagnostics, "jaeger_health")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["healthy"] != "false" ||
		strings.Contains(fmt.Sprint(diagnostic), "secret storage detail") {
		t.Fatalf("unexpected Jaeger health diagnostic: %#v", diagnostic)
	}
}

func TestJaegerConnectorMapsV1HealthStatusAndKeepsFailuresUnevaluable(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		wantRuntime   int
		wantHealthy   string
		wantPartial   bool
		wantAvailable string
	}{
		{name: "ready", status: http.StatusOK, wantRuntime: 1, wantHealthy: "true", wantAvailable: "true"},
		{name: "not-ready", status: http.StatusServiceUnavailable, wantRuntime: 1, wantHealthy: "false", wantAvailable: "true"},
		{name: "unauthorized", status: http.StatusUnauthorized, wantPartial: true, wantAvailable: "false"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/services":
					fmt.Fprint(w, `{"data":[]}`)
				case "/api/dependencies":
					fmt.Fprint(w, `{"data":[]}`)
				case "/health":
					w.WriteHeader(test.status)
					fmt.Fprint(w, `runtime body must not be retained`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			connector, err := NewJaegerConnectorWithRuntimeOptions(server.URL, server.URL+"/health", 1000, time.Hour, 100, HTTPOptions{})
			if err != nil {
				t.Fatalf("new Jaeger connector: %v", err)
			}
			snapshot, err := connector.Sync(context.Background())
			if err != nil {
				t.Fatalf("sync Jaeger: %v", err)
			}
			if snapshot.Partial != test.wantPartial {
				t.Fatalf("partial=%v, want %v", snapshot.Partial, test.wantPartial)
			}
			assertResourceCount(t, snapshot, model.ResourceTypeInstance, test.wantRuntime)
			for _, resource := range snapshot.Resources {
				if resource.Type == model.ResourceTypeInstance && resource.Metadata[model.MetadataJaegerHealthy] != test.wantHealthy {
					t.Fatalf("healthy=%q, want %q", resource.Metadata[model.MetadataJaegerHealthy], test.wantHealthy)
				}
			}
			diagnostic := diagnosticByID(snapshot.Diagnostics, "jaeger_health")
			if diagnostic.Metadata["available"] != test.wantAvailable {
				t.Fatalf("unexpected health diagnostic: %#v", diagnostic)
			}
		})
	}
}

func TestJaegerConnectorRejectsInvalidHealthURL(t *testing.T) {
	if _, err := NewJaegerConnectorWithRuntimeOptions("http://jaeger:16686", "jaeger:13133/status", 1000, time.Hour, 100, HTTPOptions{}); err == nil {
		t.Fatal("expected invalid Jaeger health URL to fail")
	}
}

func TestJaegerConnectorDiscoversServiceDependencies(t *testing.T) {
	var dependencyQuery map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":["checkout","payments"]}`)
		case "/api/operations":
			fmt.Fprint(w, `{"data":[]}`)
		case "/api/dependencies":
			dependencyQuery = map[string]string{
				"endTs":    r.URL.Query().Get("endTs"),
				"lookback": r.URL.Query().Get("lookback"),
			}
			fmt.Fprint(w, `{"data":[{"parent":" checkout ","child":"payments","callCount":3},{"parent":"checkout","child":"payments","callCount":4},{"parent":"payments","child":"inventory","callCount":2},{"parent":"checkout","child":"checkout","callCount":99}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithTopologyOptions(server.URL, 1000, 6*time.Hour, 100, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync jaeger topology: %v", err)
	}
	if snapshot.Partial {
		t.Fatalf("expected complete topology snapshot, got %#v", snapshot.Diagnostics)
	}
	if dependencyQuery["endTs"] == "" || dependencyQuery["lookback"] != "21600000" {
		t.Fatalf("unexpected dependency query: %#v", dependencyQuery)
	}
	assertResourceCount(t, snapshot, model.ResourceTypeService, 3)
	assertRelationship(t, snapshot, model.RelationshipDependsOn, model.ResourceTypeService, model.ResourceTypeService)

	dependencyCounts := map[string]string{}
	for _, relationship := range snapshot.Relationships {
		if relationship.Type != model.RelationshipDependsOn {
			continue
		}
		from, _ := resourceByID(snapshot, relationship.FromID)
		to, _ := resourceByID(snapshot, relationship.ToID)
		dependencyCounts[from.Name+"->"+to.Name] = relationship.Metadata[model.MetadataAPMTopologyCallCount]
		if relationship.Metadata[model.MetadataAPMLookback] != "6h0m0s" {
			t.Fatalf("unexpected relationship lookback: %#v", relationship.Metadata)
		}
	}
	if fmt.Sprint(dependencyCounts) != "map[checkout->payments:7 payments->inventory:2]" {
		t.Fatalf("unexpected normalized dependencies: %#v", dependencyCounts)
	}
	for _, resource := range snapshot.Resources {
		if resource.Type != model.ResourceTypeService {
			continue
		}
		if resource.Metadata[model.MetadataAPMTopologyDiscoveryAvailable] != "true" ||
			resource.Metadata[model.MetadataAPMTopologyDependencyCount] != "2" ||
			resource.Metadata[model.MetadataAPMTopologyDependencyLimit] != "100" {
			t.Fatalf("unexpected topology metadata: %#v", resource.Metadata)
		}
		if resource.Name == "inventory" && resource.Metadata[model.MetadataAPMCatalogService] != "false" {
			t.Fatalf("expected topology-only service marker, got %#v", resource.Metadata)
		}
	}
	diagnostic := diagnosticByID(snapshot.Diagnostics, "jaeger_dependencies")
	if diagnostic.ID == "" || diagnostic.Status != model.ExecutionStatusSucceeded ||
		diagnostic.Metadata["dependency_count"] != "2" ||
		diagnostic.Metadata["lookback"] != "6h0m0s" {
		t.Fatalf("unexpected dependency diagnostic: %#v", diagnostic)
	}
}

func TestJaegerConnectorAcceptsBareDependencyResponseAndMarksLimitPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":["a","b","c"]}`)
		case "/api/operations":
			fmt.Fprint(w, `{"data":[]}`)
		case "/api/dependencies":
			fmt.Fprint(w, `[{"parent":"c","child":"a","callCount":1},{"parent":"a","child":"c","callCount":2},{"parent":"a","child":"b","callCount":3}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithTopologyOptions(server.URL, 1000, time.Hour, 2, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync jaeger topology: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected dependency limit to mark snapshot partial")
	}
	dependencyNames := make([]string, 0)
	for _, relationship := range snapshot.Relationships {
		if relationship.Type != model.RelationshipDependsOn {
			continue
		}
		from, _ := resourceByID(snapshot, relationship.FromID)
		to, _ := resourceByID(snapshot, relationship.ToID)
		dependencyNames = append(dependencyNames, from.Name+"->"+to.Name)
	}
	sort.Strings(dependencyNames)
	if fmt.Sprint(dependencyNames) != "[a->b a->c]" {
		t.Fatalf("expected deterministic dependency cap, got %#v", dependencyNames)
	}
	diagnostic := diagnosticByID(snapshot.Diagnostics, "jaeger_dependencies")
	if diagnostic.Status != model.ExecutionStatusWarning ||
		diagnostic.Metadata["dependency_count"] != "3" ||
		diagnostic.Metadata["truncated"] != "true" {
		t.Fatalf("unexpected truncated dependency diagnostic: %#v", diagnostic)
	}
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService &&
			resource.Metadata[model.MetadataAPMTopologyDiscoveryTruncated] != "true" {
			t.Fatalf("expected truncated service topology metadata: %#v", resource.Metadata)
		}
	}
}

func TestJaegerConnectorContinuesWhenDependencyDiscoveryFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/services":
			fmt.Fprint(w, `{"data":["checkout"]}`)
		case "/api/operations":
			fmt.Fprint(w, `{"data":["GET /checkout"]}`)
		case "/api/dependencies":
			http.Error(w, "dependency store unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connector, err := NewJaegerConnectorWithTopologyOptions(server.URL, 1000, 24*time.Hour, 100, HTTPOptions{})
	if err != nil {
		t.Fatalf("new jaeger connector: %v", err)
	}
	snapshot, err := connector.Sync(context.Background())
	if err != nil {
		t.Fatalf("dependency enrichment should be optional: %v", err)
	}
	if !snapshot.Partial {
		t.Fatal("expected dependency failure to mark snapshot partial")
	}
	assertResourceCount(t, snapshot, model.ResourceTypeTraceOperation, 1)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService &&
			resource.Metadata[model.MetadataAPMTopologyDiscoveryAvailable] != "false" {
			t.Fatalf("expected unavailable topology metadata: %#v", resource.Metadata)
		}
	}
	if diagnosticByID(snapshot.Diagnostics, "jaeger_dependencies").Status != model.ExecutionStatusWarning {
		t.Fatalf("expected warning dependency diagnostic: %#v", snapshot.Diagnostics)
	}
}

func TestJaegerConnectorRejectsExcessiveDependencyLimit(t *testing.T) {
	if _, err := NewJaegerConnectorWithTopologyOptions("http://jaeger:16686", 1000, time.Hour, maxJaegerDependencyLimit+1, HTTPOptions{}); err == nil {
		t.Fatal("expected excessive dependency limit to fail")
	}
}
