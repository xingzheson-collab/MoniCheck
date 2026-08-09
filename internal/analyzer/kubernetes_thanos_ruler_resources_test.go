package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerResourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := thanosRulerResourceRequirementsResource("bounded")
	invalid := thanosRulerResourceRequirementsResource("invalid")
	invalid.Metadata["thanos_ruler_resource_invalid_setting_count"] = "2"
	missingRequests := thanosRulerResourceRequirementsResource("missing-requests")
	missingRequests.Metadata["thanos_ruler_cpu_request_positive"] = "false"
	missingLimit := thanosRulerResourceRequirementsResource("missing-limit")
	missingLimit.Metadata["thanos_ruler_memory_limit_positive"] = "false"
	wrongKind := thanosRulerResourceRequirementsResource("wrong-kind")
	wrongKind.Metadata["kubernetes_kind"] = "Pod"
	for _, resource := range []model.Resource{bounded, invalid, missingRequests, missingLimit, wrongKind} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerResourcesAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesThanosRulerWithoutResourceRequestsAnalyzer(), missingRequests.ID, model.SeverityWarning},
		{NewKubernetesThanosRulerWithoutMemoryLimitAnalyzer(), missingLimit.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerResourceRequirementsResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_resource_metadata": "true", "thanos_ruler_resource_invalid_setting_count": "0", "thanos_ruler_cpu_request_positive": "true", "thanos_ruler_memory_request_positive": "true", "thanos_ruler_memory_limit_positive": "true"}}
}
