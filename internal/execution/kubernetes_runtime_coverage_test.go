package execution

import (
	"context"
	"io"
	"testing"

	"monicheck/internal/analyzer"
	"monicheck/internal/logger"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestReconcileKubernetesRuntimeCoverage(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		runtimeCoverageResource("runtime-tsdb", model.ResourceTypeTSDB, "prometheus", "prometheus", map[string]string{
			model.MetadataTargetsDiscoveryAvailable: "true",
		}),
		runtimeCoverageResource("prom-a", model.ResourceTypeTSDB, "kubernetes", "monitoring/a", map[string]string{
			"kubernetes_kind":              "Prometheus",
			"prometheus_desired_pod_count": "1",
		}),
		runtimeCoverageResource("prom-b", model.ResourceTypeTSDB, "kubernetes", "monitoring/b", map[string]string{
			"kubernetes_kind":              "Prometheus",
			"prometheus_desired_pod_count": "1",
		}),
		runtimeCoverageResource("runtime-covered", model.ResourceTypeTarget, "prometheus", "http://api/metrics", map[string]string{
			model.MetadataOperatorMonitorKind:      "ServiceMonitor",
			model.MetadataOperatorMonitorNamespace: "prod",
			model.MetadataOperatorMonitorName:      "covered",
			model.MetadataOperatorMonitorEndpoint:  "0",
		}),
		runtimeCoverageResource("runtime-ambiguous", model.ResourceTypeTarget, "prometheus", "http://ambiguous/metrics", map[string]string{
			model.MetadataOperatorMonitorKind:      "ServiceMonitor",
			model.MetadataOperatorMonitorNamespace: "prod",
			model.MetadataOperatorMonitorName:      "ambiguous",
		}),
		runtimeDroppedCoverageResource("runtime-covered-dropped", "covered"),
		runtimeDroppedCoverageResource("runtime-all-dropped-a", "all-dropped"),
		runtimeDroppedCoverageResource("runtime-all-dropped-b", "all-dropped"),
		kubernetesRuntimeCoverageTarget("covered", "prod"),
		kubernetesRuntimeCoverageTarget("ambiguous", "prod"),
		kubernetesRuntimeCoverageTarget("all-dropped", "prod"),
		kubernetesRuntimeCoverageTarget("missing", "prod"),
		kubernetesRuntimeCoverageTarget("unknown", "staging"),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	engine := NewEngine(store, nil, analyzer.NewRegistry(), logger.New(io.Discard, "error"))
	if err := engine.reconcileKubernetesRuntimeCoverage(ctx); err != nil {
		t.Fatalf("reconcile runtime coverage: %v", err)
	}

	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-covered", "true", "1", "kind_namespace")
	assertRuntimeEndpointCoverageMetadata(t, ctx, store, "k8s-covered", "true", "1", "1", "1")
	assertRuntimeDroppedCoverageMetadata(t, ctx, store, "k8s-covered", "1", "2", "0.5000")
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-ambiguous", "true", "1", "kind_namespace")
	assertRuntimeEndpointCoverageMetadata(t, ctx, store, "k8s-ambiguous", "false", "", "", "")
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-all-dropped", "true", "0", "kind_namespace")
	assertRuntimeDroppedCoverageMetadata(t, ctx, store, "k8s-all-dropped", "2", "2", "1.0000")
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-missing", "true", "0", "kind_namespace")
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-unknown", "false", "", "")

	runtimeTSDB := resources[0]
	runtimeTSDB.Metadata[model.MetadataTargetsDiscoveryAvailable] = "false"
	if err := store.Resources.Upsert(ctx, runtimeTSDB); err != nil {
		t.Fatalf("update runtime TSDB: %v", err)
	}
	if err := engine.reconcileKubernetesRuntimeCoverage(ctx); err != nil {
		t.Fatalf("reconcile unavailable runtime coverage: %v", err)
	}
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-missing", "false", "", "")
	assertRuntimeEndpointCoverageMetadata(t, ctx, store, "k8s-covered", "false", "", "", "")
}

func TestReconcileKubernetesRuntimeCoverageWithPrometheusAgent(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		runtimeCoverageResource("runtime-agent", model.ResourceTypeTSDB, "prometheus", "agent", map[string]string{
			model.MetadataTargetsDiscoveryAvailable: "true",
		}),
		runtimeCoverageResource("manifest-agent", model.ResourceTypeTSDB, "kubernetes", "monitoring/edge", map[string]string{
			"kubernetes_kind":              "PrometheusAgent",
			"prometheus_desired_pod_count": "1",
		}),
		kubernetesRuntimeCoverageTarget("missing", "edge"),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	engine := NewEngine(store, nil, analyzer.NewRegistry(), logger.New(io.Discard, "error"))
	if err := engine.reconcileKubernetesRuntimeCoverage(ctx); err != nil {
		t.Fatalf("reconcile runtime coverage: %v", err)
	}
	assertRuntimeCoverageMetadata(t, ctx, store, "k8s-missing", "true", "0", "singleton")
}

func runtimeCoverageResource(id string, resourceType model.ResourceType, system string, name string, metadata map[string]string) model.Resource {
	return model.Resource{
		ID: id, UID: id, Type: resourceType, Name: name, Source: model.SourceInfo{System: system}, Metadata: metadata, Status: model.ResourceStatusActive,
	}
}

func runtimeDroppedCoverageResource(id string, monitorName string) model.Resource {
	resource := runtimeCoverageResource(id, model.ResourceTypeTarget, "prometheus", id, map[string]string{
		model.MetadataTargetState:              "dropped",
		model.MetadataOperatorMonitorKind:      "ServiceMonitor",
		model.MetadataOperatorMonitorNamespace: "prod",
		model.MetadataOperatorMonitorName:      monitorName,
		model.MetadataOperatorMonitorEndpoint:  "0",
	})
	resource.Status = model.ResourceStatusDeprecated
	return resource
}

func kubernetesRuntimeCoverageTarget(name string, namespace string) model.Resource {
	return runtimeCoverageResource("k8s-"+name, model.ResourceTypeTarget, "kubernetes", namespace+"/"+name, map[string]string{
		"kubernetes_kind":                   "ServiceMonitor",
		"namespace":                         namespace,
		"prometheus_selection_candidate":    "true",
		"prometheus_nonzero_selected_count": "1",
		"endpoint_count":                    "2",
	})
}

func assertRuntimeEndpointCoverageMetadata(t *testing.T, ctx context.Context, store *storage.Store, id string, evaluable string, covered string, missingCount string, missing string) {
	t.Helper()
	resource, found, err := store.Resources.Get(ctx, id)
	if err != nil || !found {
		t.Fatalf("get resource %s: found=%t err=%v", id, found, err)
	}
	if resource.Metadata[model.MetadataRuntimeEndpointEvaluable] != evaluable || resource.Metadata[model.MetadataRuntimeEndpointCount] != covered || resource.Metadata[model.MetadataRuntimeMissingEndpointCount] != missingCount || resource.Metadata[model.MetadataRuntimeMissingEndpoints] != missing {
		t.Fatalf("unexpected runtime endpoint coverage metadata for %s: %#v", id, resource.Metadata)
	}
}

func assertRuntimeDroppedCoverageMetadata(t *testing.T, ctx context.Context, store *storage.Store, id string, dropped string, observed string, ratio string) {
	t.Helper()
	resource, found, err := store.Resources.Get(ctx, id)
	if err != nil || !found {
		t.Fatalf("get resource %s: found=%t err=%v", id, found, err)
	}
	if resource.Metadata[model.MetadataRuntimeDroppedTargetCount] != dropped || resource.Metadata[model.MetadataRuntimeObservedTargetCount] != observed || resource.Metadata[model.MetadataRuntimeDroppedTargetRatio] != ratio {
		t.Fatalf("unexpected runtime dropped coverage metadata for %s: %#v", id, resource.Metadata)
	}
}

func assertRuntimeCoverageMetadata(t *testing.T, ctx context.Context, store *storage.Store, id string, evaluable string, count string, scope string) {
	t.Helper()
	resource, found, err := store.Resources.Get(ctx, id)
	if err != nil {
		t.Fatalf("get resource %s: %v", id, err)
	}
	if !found {
		t.Fatalf("resource %s was not found", id)
	}
	if resource.Metadata[model.MetadataRuntimeCoverageEvaluable] != evaluable || resource.Metadata[model.MetadataRuntimeTargetCount] != count || resource.Metadata[model.MetadataRuntimeCoverageScope] != scope {
		t.Fatalf("unexpected runtime coverage metadata for %s: %#v", id, resource.Metadata)
	}
}
