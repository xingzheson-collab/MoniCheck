package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesScrapeTimingAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesScrapeTimingResource("invalid-workload", model.ResourceTypeTSDB, "Prometheus", map[string]string{"prometheus_scrape_timing_invalid_setting_count": "2"}),
		kubernetesScrapeTimingResource("invalid-monitor", model.ResourceTypeTarget, "ServiceMonitor", map[string]string{"monitor_scrape_timing_invalid_setting_count": "1"}),
		kubernetesScrapeTimingResource("workload-conflict", model.ResourceTypeTSDB, "PrometheusAgent", map[string]string{"prometheus_scrape_timeout_exceeds_interval": "true"}),
		kubernetesScrapeTimingResource("monitor-conflict", model.ResourceTypeTarget, "PodMonitor", map[string]string{"monitor_scrape_timeout_exceeds_interval_count": "1", "prometheus_scrape_timeout_conflict_count": "2"}),
		kubernetesScrapeTimingResource("clean", model.ResourceTypeTarget, "Probe", map[string]string{}),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	invalid, err := NewKubernetesInvalidScrapeTimingAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(invalid) != 2 {
		t.Fatalf("unexpected invalid scrape timing findings: %#v err=%v", invalid, err)
	}
	conflicts, err := NewKubernetesScrapeTimeoutExceedsIntervalAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(conflicts) != 2 {
		t.Fatalf("unexpected scrape timing conflict findings: %#v err=%v", conflicts, err)
	}
}

func kubernetesScrapeTimingResource(id string, resourceType model.ResourceType, kind string, extra map[string]string) model.Resource {
	metadata := map[string]string{"kubernetes_kind": kind, "namespace": "monitoring"}
	for key, value := range extra {
		metadata[key] = value
	}
	return model.Resource{ID: id, UID: id, Type: resourceType, Name: "monitoring/" + id, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: metadata}
}
