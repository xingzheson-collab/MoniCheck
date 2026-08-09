package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerGRPCTLSAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerGRPCTLSResource("invalid")
	invalid.Metadata["thanos_ruler_grpc_tls_declared"] = "true"
	invalid.Metadata["thanos_ruler_grpc_tls_invalid_setting_count"] = "2"
	unsupported := thanosRulerGRPCTLSResource("unsupported")
	unsupported.Metadata["thanos_ruler_grpc_tls_declared"] = "true"
	unsupported.Metadata["thanos_ruler_grpc_tls_unsupported_setting_count"] = "1"
	plaintext := thanosRulerGRPCTLSResource("plaintext")
	for _, resource := range []model.Resource{invalid, unsupported, plaintext} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerGRPCTLSAnalyzer(), invalid.ID},
		{NewKubernetesUnsupportedThanosRulerGRPCTLSAnalyzer(), unsupported.ID},
		{NewKubernetesThanosRulerWithoutGRPCTLSAnalyzer(), plaintext.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerGRPCTLSResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_replicas": "1", "thanos_ruler_grpc_tls_metadata": "true", "thanos_ruler_grpc_tls_declared": "false", "thanos_ruler_grpc_tls_complete": "false", "thanos_ruler_grpc_tls_invalid_setting_count": "0", "thanos_ruler_grpc_tls_unsupported_setting_count": "0", "thanos_ruler_listen_local_valid": "false", "thanos_ruler_listen_local_enabled": "false"}}
}
