package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesHonorOverrideAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesHonorMonitor("risky", "ServiceMonitor", map[string]string{"monitor_honor_labels_count": "2", "prometheus_honor_labels_unprotected_count": "1", "monitor_explicit_honor_timestamps_count": "1", "prometheus_honor_timestamps_unprotected_count": "1"}),
		kubernetesHonorMonitor("protected", "PodMonitor", map[string]string{"monitor_honor_labels_count": "1", "prometheus_honor_labels_unprotected_count": "0", "monitor_explicit_honor_timestamps_count": "1", "prometheus_honor_timestamps_unprotected_count": "0"}),
		kubernetesHonorMonitor("config", "ScrapeConfig", map[string]string{"monitor_honor_labels_count": "1", "prometheus_honor_labels_unprotected_count": "0", "monitor_explicit_honor_timestamps_count": "1", "prometheus_honor_timestamps_unprotected_count": "1"}),
		kubernetesHonorMonitor("unselected", "ServiceMonitor", map[string]string{"prometheus_selected_count": "0", "monitor_honor_labels_count": "1", "prometheus_honor_labels_unprotected_count": "1"}),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	labels, err := NewKubernetesMonitorHonorLabelsNotOverriddenAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(labels) != 1 || labels[0].Resource.ID != "risky" || labels[0].Category != model.FindingCategoryQuality {
		t.Fatalf("unexpected honor labels findings: %#v err=%v", labels, err)
	}
	timestamps, err := NewKubernetesMonitorHonorTimestampsNotOverriddenAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(timestamps) != 1 || timestamps[0].Resource.ID != "risky" || timestamps[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected honor timestamps findings: %#v err=%v", timestamps, err)
	}
}

func kubernetesHonorMonitor(id, kind string, extra map[string]string) model.Resource {
	metadata := map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_selected_count": "1"}
	for key, value := range extra {
		metadata[key] = value
	}
	return model.Resource{ID: id, UID: id, Type: model.ResourceTypeTarget, Name: "monitoring/" + id, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: metadata}
}
