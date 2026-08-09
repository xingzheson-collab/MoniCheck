package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerWorkloadIdentityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerWorkloadIdentityResource("invalid")
	invalid.Metadata["thanos_ruler_service_name_declared"] = "true"
	invalid.Metadata["thanos_ruler_service_name_valid"] = "false"
	shared := thanosRulerWorkloadIdentityResource("shared")
	shared.Metadata["thanos_ruler_shared_service_count"] = "2"
	for _, resource := range []model.Resource{invalid, shared} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerWorkloadIdentityAnalyzer(), invalid.ID},
		{NewKubernetesSharedThanosRulerGoverningServiceAnalyzer(), shared.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerWorkloadIdentityResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_workload_identity_metadata": "true", "thanos_ruler_service_name_declared": "false", "thanos_ruler_service_name_valid": "false", "thanos_ruler_service_account_name_declared": "false", "thanos_ruler_service_account_name_valid": "false", "thanos_ruler_shared_service_count": "0"}}
}
