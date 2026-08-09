package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerTerminationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := thanosRulerTerminationResource("valid", "true", "120")
	immediate := thanosRulerTerminationResource("immediate", "true", "0")
	invalid := thanosRulerTerminationResource("invalid", "false", "0")
	for _, resource := range []model.Resource{valid, immediate, invalid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerTerminationGraceAnalyzer(), invalid.ID},
		{NewKubernetesImmediateThanosRulerTerminationAnalyzer(), immediate.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != model.SeverityCritical {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerTerminationResource(name, valid, seconds string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_termination_grace_declared": "true", "thanos_ruler_termination_grace_valid": valid, "thanos_ruler_termination_grace_seconds": seconds}}
}
