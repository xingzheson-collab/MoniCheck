package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesRemoteWriteExporterAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := kubernetesRemoteWriteExporter("valid")
	broken := kubernetesRemoteWriteExporter("broken")
	broken.Metadata["remote_write_destination_declared"] = "false"
	broken.Metadata["remote_write_url_valid"] = "false"
	broken.Metadata["remote_write_auth_method_count"] = "2"
	broken.Metadata["remote_write_queue_capacity_declared"] = "true"
	broken.Metadata["remote_write_queue_capacity"] = "-1"
	broken.Metadata["remote_write_queue_min_shards_declared"] = "true"
	broken.Metadata["remote_write_queue_min_shards"] = "8"
	broken.Metadata["remote_write_queue_max_shards_declared"] = "true"
	broken.Metadata["remote_write_queue_max_shards"] = "2"
	insecure := kubernetesRemoteWriteExporter("insecure")
	insecure.Metadata["remote_write_url_scheme"] = "http"
	insecure.Metadata["remote_write_tls_insecure"] = "true"
	for _, resource := range []model.Resource{valid, broken, insecure} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	tests := []struct {
		name       string
		analyzer   Analyzer
		resourceID string
		category   model.FindingCategory
	}{
		{"destination", NewKubernetesInvalidRemoteWriteDestinationAnalyzer(), broken.ID, model.FindingCategoryReliability},
		{"transport", NewKubernetesInsecureRemoteWriteAnalyzer(), insecure.ID, model.FindingCategorySecurity},
		{"auth", NewKubernetesConflictingRemoteWriteAuthAnalyzer(), broken.ID, model.FindingCategoryConfiguration},
		{"queue", NewKubernetesInvalidRemoteWriteQueueAnalyzer(), broken.ID, model.FindingCategoryConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resourceID || findings[0].Category != test.category {
				t.Fatalf("unexpected findings: %#v err=%v", findings, err)
			}
		})
	}
}

func TestKubernetesRemoteWriteNotSelectedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	unselected := kubernetesRemoteWriteExporter("unselected")
	unselected.Metadata["remote_write_origin"] = "crd"
	unselected.Metadata["remote_write_selection_evaluable"] = "true"
	unselected.Metadata["remote_write_selected_count"] = "0"
	selected := kubernetesRemoteWriteExporter("selected")
	selected.Metadata["remote_write_origin"] = "crd"
	selected.Metadata["remote_write_selection_evaluable"] = "true"
	selected.Metadata["remote_write_selected_count"] = "1"
	unknown := kubernetesRemoteWriteExporter("unknown")
	unknown.Metadata["remote_write_origin"] = "crd"
	unknown.Metadata["remote_write_selection_evaluable"] = "false"
	unknown.Metadata["remote_write_selected_count"] = "0"
	for _, resource := range []model.Resource{unselected, selected, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesRemoteWriteNotSelectedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != unselected.ID || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func TestKubernetesDuplicateRemoteWriteNameAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	duplicate := model.Resource{ID: "duplicate", UID: "duplicate", Type: model.ResourceTypeTSDB, Name: "monitoring/main", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Prometheus", "namespace": "monitoring", "remote_write_duplicate_name_count": "1"}}
	valid := model.Resource{ID: "valid", UID: "valid", Type: model.ResourceTypeInstance, Name: "monitoring/ruler", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "remote_write_duplicate_name_count": "0"}}
	for _, resource := range []model.Resource{duplicate, valid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesDuplicateRemoteWriteNameAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != duplicate.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func kubernetesRemoteWriteExporter(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeExporter, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":                         "RemoteWrite",
		"namespace":                               "monitoring",
		"remote_write_origin":                     "inline",
		"remote_write_destination_declared":       "true",
		"remote_write_url_valid":                  "true",
		"remote_write_url_scheme":                 "https",
		"remote_write_tls_insecure":               "false",
		"remote_write_auth_method_count":          "1",
		"remote_write_queue_capacity_declared":    "false",
		"remote_write_queue_min_shards_declared":  "false",
		"remote_write_queue_max_shards_declared":  "false",
		"remote_write_queue_max_samples_declared": "false",
	}}
}
