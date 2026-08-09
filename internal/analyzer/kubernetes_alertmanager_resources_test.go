package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerResourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := alertmanagerResourceRequirementsResource("bounded")
	invalid := alertmanagerResourceRequirementsResource("invalid")
	invalid.Metadata["alertmanager_resource_invalid_setting_count"] = "2"
	missingRequests := alertmanagerResourceRequirementsResource("missing-requests")
	missingRequests.Metadata["alertmanager_cpu_request_positive"] = "false"
	missingLimit := alertmanagerResourceRequirementsResource("missing-limit")
	missingLimit.Metadata["alertmanager_memory_limit_positive"] = "false"
	for _, resource := range []model.Resource{bounded, invalid, missingRequests, missingLimit} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerResourcesAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerWithoutResourceRequestsAnalyzer(), missingRequests.ID},
		{NewKubernetesAlertmanagerWithoutMemoryLimitAnalyzer(), missingLimit.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerResourceRequirementsResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_resource_metadata": "true", "alertmanager_resource_invalid_setting_count": "0", "alertmanager_cpu_request_positive": "true", "alertmanager_memory_request_positive": "true", "alertmanager_memory_limit_positive": "true"}}
}
