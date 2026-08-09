package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerWebAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerWebResource("invalid")
	invalid.Metadata["thanos_ruler_web_invalid_setting_count"] = "3"
	http2 := thanosRulerWebResource("http2")
	http2.Metadata["thanos_ruler_web_http2_declared"] = "true"
	http2.Metadata["thanos_ruler_web_http2_valid"] = "true"
	http2.Metadata["thanos_ruler_web_http2_enabled"] = "true"
	for _, resource := range []model.Resource{invalid, http2} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerWebConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesThanosRulerHTTP2WithoutTLSAnalyzer(), http2.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerWebResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_web_metadata": "true", "thanos_ruler_web_invalid_setting_count": "0", "thanos_ruler_web_tls_complete": "false", "thanos_ruler_web_http2_valid": "false", "thanos_ruler_web_http2_enabled": "false"}}
}
