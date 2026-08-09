package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusStorageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := kubernetesPrometheusStorageResource("valid", "Prometheus")
	ephemeral := kubernetesPrometheusStorageResource("ephemeral", "Prometheus")
	ephemeral.Metadata["prometheus_storage_mode"] = "default-empty-dir"
	agent := kubernetesPrometheusStorageResource("agent", "PrometheusAgent")
	agent.Metadata["prometheus_storage_mode"] = "ephemeral"
	agent.Metadata["prometheus_wal_compression_declared"] = "true"
	agent.Metadata["prometheus_wal_compression_enabled"] = "false"
	conflict := kubernetesPrometheusStorageResource("conflict", "Prometheus")
	conflict.Metadata["prometheus_storage_option_count"] = "2"
	implicit := kubernetesPrometheusStorageResource("implicit", "Prometheus")
	implicit.Metadata["prometheus_retention_declared"] = "false"
	implicit.Metadata["prometheus_retention_size_declared"] = "false"
	invalid := kubernetesPrometheusStorageResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_retention_declared"] = "true"
	invalid.Metadata["prometheus_retention_valid"] = "false"
	undersized := kubernetesPrometheusStorageResource("undersized", "Prometheus")
	undersized.Metadata["prometheus_retention_size_bytes"] = "107374182400"
	undersized.Metadata["prometheus_pvc_request_bytes"] = "85899345920"
	undersized.Metadata["prometheus_retention_exceeds_pvc"] = "true"
	walOff := kubernetesPrometheusStorageResource("wal-off", "Prometheus")
	walOff.Metadata["prometheus_wal_compression_declared"] = "true"
	walOff.Metadata["prometheus_wal_compression_enabled"] = "false"
	compactionOff := kubernetesPrometheusStorageResource("compaction-off", "Prometheus")
	compactionOff.Metadata["prometheus_disable_compaction"] = "true"
	compactionOff.Metadata["prometheus_thanos_object_storage_declared"] = "false"
	thanosOwned := kubernetesPrometheusStorageResource("thanos-owned", "Prometheus")
	thanosOwned.Metadata["prometheus_disable_compaction"] = "true"
	thanosOwned.Metadata["prometheus_thanos_object_storage_declared"] = "true"
	for _, resource := range []model.Resource{valid, ephemeral, agent, conflict, implicit, invalid, undersized, walOff, compactionOff, thanosOwned} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	tests := []struct {
		name      string
		analyzer  Analyzer
		resources map[string]model.Severity
		category  model.FindingCategory
	}{
		{"ephemeral", NewKubernetesEphemeralPrometheusStorageAnalyzer(), map[string]model.Severity{ephemeral.ID: model.SeverityCritical, agent.ID: model.SeverityWarning}, model.FindingCategoryReliability},
		{"conflict", NewKubernetesConflictingPrometheusStorageAnalyzer(), map[string]model.Severity{conflict.ID: model.SeverityCritical}, model.FindingCategoryConfiguration},
		{"implicit", NewKubernetesImplicitPrometheusRetentionAnalyzer(), map[string]model.Severity{implicit.ID: model.SeverityWarning}, model.FindingCategoryReliability},
		{"invalid", NewKubernetesInvalidPrometheusRetentionAnalyzer(), map[string]model.Severity{invalid.ID: model.SeverityCritical}, model.FindingCategoryConfiguration},
		{"undersized", NewKubernetesRetentionExceedsPVCAnalyzer(), map[string]model.Severity{undersized.ID: model.SeverityCritical}, model.FindingCategoryReliability},
		{"wal", NewKubernetesWALCompressionDisabledAnalyzer(), map[string]model.Severity{agent.ID: model.SeverityWarning, walOff.ID: model.SeverityWarning}, model.FindingCategoryCost},
		{"compaction", NewKubernetesDisabledCompactionWithoutObjectStorageAnalyzer(), map[string]model.Severity{compactionOff.ID: model.SeverityWarning}, model.FindingCategoryReliability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil || len(findings) != len(test.resources) {
				t.Fatalf("unexpected findings: %#v err=%v", findings, err)
			}
			for _, finding := range findings {
				severity, ok := test.resources[finding.Resource.ID]
				if !ok || finding.Severity != severity || finding.Category != test.category {
					t.Fatalf("unexpected finding: %#v", finding)
				}
			}
		})
	}
}

func kubernetesPrometheusStorageResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":                     kind,
		"namespace":                           "monitoring",
		"prometheus_storage_mode":             "pvc",
		"prometheus_storage_option_count":     "1",
		"prometheus_pvc_request_declared":     "true",
		"prometheus_pvc_request_valid":        "true",
		"prometheus_pvc_request_bytes":        "107374182400",
		"prometheus_retention_declared":       "true",
		"prometheus_retention_valid":          "true",
		"prometheus_retention_seconds":        "1296000",
		"prometheus_retention_size_declared":  "true",
		"prometheus_retention_size_valid":     "true",
		"prometheus_retention_size_bytes":     "96636764160",
		"prometheus_retention_exceeds_pvc":    "false",
		"prometheus_wal_compression_declared": "false",
		"prometheus_wal_compression_enabled":  "true",
	}}
}
