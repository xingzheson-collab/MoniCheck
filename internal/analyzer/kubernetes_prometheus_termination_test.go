package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusTerminationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := prometheusTerminationResource("valid", "Prometheus", "true", "120")
	immediate := prometheusTerminationResource("immediate", "PrometheusAgent", "true", "0")
	invalid := prometheusTerminationResource("invalid", "Prometheus", "false", "0")
	for _, resource := range []model.Resource{valid, immediate, invalid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	for _, test := range []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusTerminationGraceAnalyzer(), invalid.ID},
		{NewKubernetesImmediatePrometheusTerminationAnalyzer(), immediate.ID},
	} {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != model.SeverityCritical {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusTerminationResource(name, kind, valid, seconds string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_termination_grace_declared": "true", "prometheus_termination_grace_valid": valid, "prometheus_termination_grace_seconds": seconds}}
}
