package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerStorageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := thanosRulerStorageResource("valid")
	invalidStorage := thanosRulerStorageResource("invalid-storage")
	invalidStorage.Metadata["thanos_ruler_storage_invalid_setting_count"] = "2"
	conflict := thanosRulerStorageResource("conflict")
	conflict.Metadata["thanos_ruler_storage_option_count"] = "2"
	ephemeral := thanosRulerStorageResource("ephemeral")
	ephemeral.Metadata["thanos_ruler_storage_mode"] = "default-empty-dir"
	implicit := thanosRulerStorageResource("implicit")
	implicit.Metadata["thanos_ruler_retention_declared"] = "false"
	implicit.Metadata["thanos_ruler_retention_valid"] = "false"
	invalidRetention := thanosRulerStorageResource("invalid-retention")
	invalidRetention.Metadata["thanos_ruler_retention_valid"] = "false"
	ignored := thanosRulerStorageResource("ignored")
	ignored.Metadata["thanos_ruler_stateless_mode"] = "true"
	statelessEphemeral := thanosRulerStorageResource("stateless-ephemeral")
	statelessEphemeral.Metadata["thanos_ruler_stateless_mode"] = "true"
	statelessEphemeral.Metadata["thanos_ruler_storage_mode"] = "default-empty-dir"
	statelessEphemeral.Metadata["thanos_ruler_retention_declared"] = "false"
	statelessEphemeral.Metadata["thanos_ruler_retention_valid"] = "false"
	for _, resource := range []model.Resource{valid, invalidStorage, conflict, ephemeral, implicit, invalidRetention, ignored, statelessEphemeral} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerStorageAnalyzer(), invalidStorage.ID, model.SeverityCritical},
		{NewKubernetesConflictingThanosRulerStorageAnalyzer(), conflict.ID, model.SeverityCritical},
		{NewKubernetesEphemeralThanosRulerStorageAnalyzer(), ephemeral.ID, model.SeverityCritical},
		{NewKubernetesImplicitThanosRulerRetentionAnalyzer(), implicit.ID, model.SeverityWarning},
		{NewKubernetesInvalidThanosRulerRetentionAnalyzer(), invalidRetention.ID, model.SeverityCritical},
		{NewKubernetesIgnoredStatelessThanosRulerRetentionAnalyzer(), ignored.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerStorageResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_storage_metadata": "true", "thanos_ruler_storage_object_valid": "true", "thanos_ruler_storage_mode": "pvc", "thanos_ruler_storage_option_count": "1", "thanos_ruler_storage_invalid_setting_count": "0", "thanos_ruler_pvc_request_declared": "true", "thanos_ruler_pvc_request_valid": "true", "thanos_ruler_retention_declared": "true", "thanos_ruler_retention_valid": "true", "thanos_ruler_retention_seconds": "1296000", "thanos_ruler_stateless_mode": "false"}}
}
