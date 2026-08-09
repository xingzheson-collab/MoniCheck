package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesRemoteReadDatasourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := kubernetesRemoteReadDatasource("valid")
	broken := kubernetesRemoteReadDatasource("broken")
	broken.Metadata["remote_read_destination_declared"] = "false"
	broken.Metadata["remote_read_url_valid"] = "false"
	broken.Metadata["remote_read_auth_method_count"] = "2"
	broken.Metadata["remote_read_read_recent"] = "true"
	broken.Metadata["remote_read_filter_external_labels_declared"] = "true"
	broken.Metadata["remote_read_filter_external_labels"] = "false"
	broken.Metadata["remote_read_required_matcher_count"] = "0"
	insecure := kubernetesRemoteReadDatasource("insecure")
	insecure.Metadata["remote_read_url_scheme"] = "http"
	insecure.Metadata["remote_read_tls_insecure"] = "true"
	cleartext := kubernetesRemoteReadDatasource("cleartext")
	cleartext.Metadata["remote_read_cleartext_bearer_declared"] = "true"
	for _, resource := range []model.Resource{valid, broken, insecure, cleartext} {
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
		{"destination", NewKubernetesInvalidRemoteReadDestinationAnalyzer(), broken.ID, model.FindingCategoryReliability},
		{"transport", NewKubernetesInsecureRemoteReadAnalyzer(), insecure.ID, model.FindingCategorySecurity},
		{"auth", NewKubernetesConflictingRemoteReadAuthAnalyzer(), broken.ID, model.FindingCategoryConfiguration},
		{"broad", NewKubernetesBroadRemoteReadAnalyzer(), broken.ID, model.FindingCategoryCost},
		{"cleartext bearer", NewKubernetesCleartextRemoteReadBearerAnalyzer(), cleartext.ID, model.FindingCategorySecurity},
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

func TestKubernetesDuplicateRemoteReadNameAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	duplicate := model.Resource{ID: "duplicate", UID: "duplicate", Type: model.ResourceTypeTSDB, Name: "monitoring/main", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Prometheus", "namespace": "monitoring", "remote_read_duplicate_name_count": "1"}}
	valid := model.Resource{ID: "valid", UID: "valid", Type: model.ResourceTypeTSDB, Name: "monitoring/other", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Prometheus", "namespace": "monitoring", "remote_read_duplicate_name_count": "0"}}
	for _, resource := range []model.Resource{duplicate, valid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesDuplicateRemoteReadNameAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != duplicate.ID {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func TestInvalidDatasourceSkipsStructurallyRedactedRemoteRead(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := kubernetesRemoteReadDatasource("redacted")
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewInvalidDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected structurally redacted datasource to be skipped, got %#v err=%v", findings, err)
	}
}

func kubernetesRemoteReadDatasource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeDatasource, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":                             "RemoteRead",
		"namespace":                                   "monitoring",
		"datasource_health_evaluable":                 "false",
		"remote_read_destination_declared":            "true",
		"remote_read_url_valid":                       "true",
		"remote_read_url_scheme":                      "https",
		"remote_read_tls_insecure":                    "false",
		"remote_read_auth_method_count":               "1",
		"remote_read_read_recent":                     "false",
		"remote_read_filter_external_labels":          "true",
		"remote_read_filter_external_labels_declared": "false",
		"remote_read_required_matcher_count":          "0",
		"remote_read_cleartext_bearer_declared":       "false",
	}}
}
